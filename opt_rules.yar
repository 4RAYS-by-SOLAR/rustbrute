rule Detect_DebugAssertions_Is_True
{
	meta:
		description = "Yara rules created by JPCERTCC (https://github.com/JPCERTCC/rust-binary-analysis-research-ja?tab=readme-ov-file)"
    strings:
        $s1 = "unsafe precondition(s) violated:"

    condition:
        $s1
}

rule Detect_OverflowCheck_Is_True
{
    strings:
        $s1 = "attempt to add with overflow"
        $s2 = "attempt to subtract with overflow"
        $s3 = "attempt to multiply with overflow"
        $s4 = "attempt to divide with overflow"
        $s5 = "attempt to calculate the remainder with overflow"
        $s6 = "attempt to negate with overflow"
        $s7 = "attempt to shift right with overflow"
        $s8 = "attempt to shift left with overflow"

    condition:
        any of them
}

rule Detect_Panic_Is_Abort
{
    strings:
        $s1 = "fatal runtime error: Rust panics must be rethrown"
        $s2 = "fatal runtime error: Rust cannot catch foreign exceptions"
        $s3 = "Rust panics cannot be copied"
        $s4 = "_CxxThrowException"

    condition:
		none of them
}