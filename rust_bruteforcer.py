import argparse
import json
import os
import pathlib
import shutil
import sqlite3
import subprocess
import yara


def load_config(path):
    """Load configuration from a JSON file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def resolve_funcs(funcs, file_path):
    """Resolve function addresses using IDA Pro."""
    funcs = [f'"{name}"' for name in funcs]
    res = []
    try:
        out = subprocess.run(
            [idat_path, "-A", "-B", f'-S"{func_finder_script}" {" ".join(funcs)}', file_path],
            capture_output=True,
            check=True
        )
        lines = out.stdout.decode().split("\n")
        for line in lines:
            if line.startswith("func_:"):
                tmp = line.strip("\n\r").split(" ")
                res.append([tmp[1], tmp[2], int(tmp[3]), int(tmp[4])])
        return res
    except subprocess.CalledProcessError as e:
        print(f"ERROR func resolve: {e}")


def check_diff_db(db_path):
    """Check the diff database for results."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM results")
    count = cur.fetchone()[0]

    if count == 0:
        cur.execute("SELECT name FROM unmatched")
        names = [row[0] for row in cur.fetchall()]
        print("Unmatched: ", " ".join(names))
        conn.close()
        return None
    elif count == 1:
        cur.execute("SELECT ratio FROM results LIMIT 1")
        ratio = cur.fetchone()[0]
        conn.close()
        return float(ratio)
    else:
        print("Undefined behaviour")
        conn.close()
        return None


def generate_combinations(options):
    """Generate all possible combinations of options."""
    if not options:
        return [{}]

    keys = list(options.keys())
    combinations = [{}]

    for key in keys:
        new_combinations = []
        for combination in combinations:
            for value in options[key]:
                new_combinations.append({**combination, key: value})
        combinations = new_combinations

    return combinations


def compile_crate(lib_str, toolchain, profile, out_dir=".", skip_install=True, clear_tmp=True):
    """Compile a Rust crate with specified options."""
    print(f"Compile {lib_str} for {toolchain}\nProfile: {profile}")

    try:
        with open('profile.json', 'w', encoding='utf-8') as f:
            json.dump({"profile": {"release": profile}}, f)

        argv = ["python", "-m", "rustbinsign.main", "-l", "DEBUG", "-o", out_dir, "download_compile", "--template", "profile.json", lib_str, toolchain]
        if skip_install:
            argv.insert(3, "--skip-install")
        if clear_tmp:
            argv.insert(3, "--clear-tmp")
        res = subprocess.run(argv, check=True, stdout=subprocess.PIPE)
        return res.stdout.decode()
    except subprocess.CalledProcessError as e:
        print(f"Compilation error: {e}")
        return None
    finally:
        if os.path.exists("profile.json"):
            os.unlink("profile.json")


def export_func_pairs(lib_func_names, lib_path, target_funcs, target_path, work_dir, diaphora_path):
    """Export function pairs using Diaphora."""
    print("Resolve lib funcs")
    real_funcs = resolve_funcs(lib_func_names, lib_path)

    if not real_funcs:
        print("ERROR with find real funcs")
        return

    # Change order
    for i in range(len(lib_func_names)):
        for j in range(len(real_funcs)):
            if real_funcs[j][0] == lib_func_names[i]:
                real_funcs[i], real_funcs[j] = real_funcs[j], real_funcs[i]

    print("Diaphora export lib funcs")
    error = 0
    success = 0

    for i, f in enumerate(real_funcs):
        try:
            prep_env = os.environ.copy()
            prep_env["DIAPHORA_AUTO"] = "1"
            prep_env["DIAPHORA_EXPORT_FILE"] = os.path.join(work_dir, f"{i}lib.db")
            prep_env["DIAPHORA_FROM_ADDRESS"] = hex(f[2])[2:]
            prep_env["DIAPHORA_TO_ADDRESS"] = hex(f[3] + 1)[2:]
            result = subprocess.run(
                [idat_path, "-A", "-B", f"-S{diaphora_path}", lib_path],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=prep_env
            )
        except subprocess.CalledProcessError as e:
            print(f"ERROR with func {f[0]}: {e}")
            error += 1
            continue
        success += 1
    print(f"Lib export. Success: {success}, Error: {error}")

    if error:
        return False

    print("Diaphora export target funcs")
    error = 0
    success = 0

    for i, f in enumerate(target_funcs):
        if os.path.exists(os.path.join(work_dir, f"{i}target.db")):
            success += 1
            continue
        try:
            prep_env = os.environ.copy()
            prep_env["DIAPHORA_AUTO"] = "1"
            prep_env["DIAPHORA_EXPORT_FILE"] = os.path.join(work_dir, f"{i}target.db")
            prep_env["DIAPHORA_FROM_ADDRESS"] = hex(f[0])[2:]
            prep_env["DIAPHORA_TO_ADDRESS"] = hex(f[1] + 1)[2:]
            subprocess.run(
                [idat_path, "-A", "-B", f"-S{diaphora_path}", target_path],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=prep_env
            )
        except subprocess.CalledProcessError as e:
            print(f"ERROR with func {i}: {e}")
            error += 1
            continue
        success += 1
    print(f"Target export. Success: {success}, Error: {error}")

    if error:
        return False
    else:
        return True


def diff(diaphora_path, lib_file, target_file):
    """Perform diff using Diaphora."""
    try:
        env = os.environ.copy()
        env["DIFFING_IGNORE_ALL_NAMES"] = "1"
        subprocess.run(
            ["python", diaphora_path, lib_file, target_file, "-o", "diff.db"],
            check=True, env=env
        )
    except subprocess.CalledProcessError as e:
        print(f"Error: funcs diff: {e}")
        return None
    ratio = check_diff_db("diff.db")

    os.unlink(lib_file)

    if os.path.exists("diff.db"):
        os.unlink("diff.db")

    return ratio


def get_similarity_rate(count, diaphora_path, work_dir="."):
    """Calculate similarity rates for function pairs."""
    file_cnt = 0
    ratios = []
    for file in os.listdir(work_dir):
        if file.endswith("lib.db"):
            lib_file = str(os.path.join(work_dir, file))
            target_file = lib_file.replace("lib.db", "target.db")
            if not os.path.exists(target_file):
                print(f"Error: cant find pair for {file}")
                continue

            ratio = diff(diaphora_path, lib_file, target_file)

            if not ratio:
                continue
            ratios.append(ratio)
            file_cnt += 1
    if file_cnt == count:
        print(f"Successfully diffing {file_cnt} files")
    else:
        print(f"Error: diffed only {file_cnt} files, instead of {count}")
    return ratios


def bruteforce_options(lib_str, toolchain, opts, lib_func_names, target_funcs, target_path, diaphora_path, work_dir=".", skip_install=True, clear_tmp=True):
    """Bruteforce compilation options to find the best similarity."""
    work_dir = pathlib.Path(work_dir).expanduser().resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    work_dir = str(work_dir).strip("\r\n")

    best_ratio = 0
    best_profile = None
    profiles = generate_combinations(opts)

    prof_cnt = len(profiles)
    cur = 1

    for profile in profiles:
        print(f"Progress: {cur}/{prof_cnt}")
        cur += 1

        lib_path = compile_crate(lib_str, toolchain, profile, work_dir, skip_install, clear_tmp)
        if not lib_path:
            print("Skip profile")
            continue

        print("Successful compilation")
        lib_path = os.path.join(work_dir, os.path.basename(os.path.normpath(lib_path)))
        lib_path = str(lib_path).strip("\r\n").replace("\r\n", "")
        
        res = export_func_pairs(lib_func_names, lib_path, target_funcs, target_path, work_dir, diaphora_path)
        if not res:
            print("Skip profile")
            continue

        ratios = get_similarity_rate(len(lib_func_names), diaphora_path, work_dir=work_dir)

        avg_ratio = sum(ratios) / len(ratios)
        print(f"Average ratio: {avg_ratio}")

        if avg_ratio > best_ratio:
            best_ratio = avg_ratio
            best_profile = profile
        print(f"Current best ratio: {best_ratio}")

    print(f"Bruteforce completed. Best ratio: {best_ratio}\nBest profile {best_profile}")


def parse_target_funcs(value_list):
    """Parse target function bounds from string list."""
    res = []
    for pair in value_list:
        if ":" not in pair:
            raise ValueError(f"Invalid target func format: {pair}")
        s, e = pair.split(":")
        res.append([int(s, 0), int(e, 0)])
    return res


def abs_path(path):
    """Get absolute path."""
    if not os.path.isabs(path):
        return os.path.abspath(path)
    return path


def get_yara_prediction(path):
    """Get YARA predictions for the file."""
    yara_path = "opt_rules.yar"

    try:
        rules = yara.compile(yara_path)
        matches = rules.match(path)
    except yara.Error as e:
        print(f"Yara error: {e}")
        return
    except Exception as e:
        print(f"Error: {e}")
        return

    if len(matches) == 0:
        print("There are no predictions")
        return
    print("Yara predictions:")
    for match in matches:
        if match.rule == "Detect_OverflowCheck_Is_True":
            print("Maybe overflow-checks is True")
        elif match.rule == "Detect_DebugAssertions_Is_True":
            print("Maybe debug-assertions is True")
        elif match.rule == "Detect_Panic_Is_Abort":
            print('Maybe panic is "abort"')


def main():
    """Main entry point."""
    opts = {
        "opt-level": [0, 1, 2, 3, "s", "z"],
        "lto": ["off"],
        "overflow-checks": [True, False],
        "debug-assertions": [True, False],
        "panic": ["unwind", "abort"],
        "codegen-units": [1, 16, 256],
        "incremental": [True],
    }

    parser = argparse.ArgumentParser()

    parser.add_argument("--config", default="settings.json", help="JSON config file")

    parser.add_argument("--lib-func-names", nargs="*", required=True, help = "List of functions names from library: func1 func2 func3 ...")
    parser.add_argument("--target-path", required=True, help = "Path to target file")
    parser.add_argument("--target-funcs", nargs="+", required=True, help="Bounds of target functions: hex_start1:hex_end1 hex_start2:hex_end2 ...")
    parser.add_argument("--lib-str", required=True, help = "Library name and version, for example tokio-1.48.0")
    parser.add_argument("--toolchain", required=True, help = "Toolchain triple, for example stable-x86_64-pc-windows-msvc")
    parser.add_argument("--work-dir", default="opt_brute")
    parser.add_argument("--skip-install", default=False, action="store_true", help = "If the toolchain is already installed, you can enable this flag, it will speed up the work")
    parser.add_argument("--clear-tmp", default=False, action="store_true", help = "When turned on, TMP/rustbinsign/ will be cleared to save disk space, but a slowdown is possible")

    args = parser.parse_args()
    cfg = load_config(args.config)

    global func_finder_script, idat_path
    func_finder_script = cfg["func_finder_script"]
    func_finder_script = abs_path(func_finder_script)

    idat_path = cfg["idat_path"]
    diaphora_path = cfg["diaphora_path"]
    diaphora_path = abs_path(diaphora_path)

    if not func_finder_script or not idat_path or not diaphora_path:
        print("Please specify the options")
        return

    if "opts" in cfg.keys():
        opts = cfg["opts"]

    target_funcs = parse_target_funcs(args.target_funcs)

    target_path = abs_path(args.target_path.replace("\r\n", ""))

    bruteforce_options(args.lib_str, args.toolchain, opts, args.lib_func_names, target_funcs, target_path, diaphora_path, args.work_dir, args.skip_install, args.clear_tmp)

    get_yara_prediction(target_path)

    if os.path.isdir(args.work_dir):
        shutil.rmtree(args.work_dir)


if __name__ == "__main__":
    main()
