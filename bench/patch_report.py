p = 'src/main.rs'
s = open(p, encoding='utf-8').read()

# 1) signatures: switch to a per-variant map, drop the old `ts`
old = """fn write_report(
    args: &Args,
    samples: &BTreeMap<usize, ours::Sample>,
    coarse: &BTreeMap<&'static str, BTreeMap<usize, others::Coarse>>,
) {
    let ts: Vec<usize> = samples.keys().copied().collect();
    let mut text = String::new();"""
new = """fn write_report(
    args: &Args,
    samples: &BTreeMap<&'static str, BTreeMap<usize, ours::Sample>>,
    coarse: &BTreeMap<&'static str, BTreeMap<usize, others::Coarse>>,
) {
    let mut text = String::new();"""
assert old in s, 'write_report head not found'
s = s.replace(old, new, 1)

# 2) drop the old single-variant `ours` block, replace it with a loop (split on markers
#    rather than retyping the block character by character)
start_marker = '    if !samples.is_empty() {\n'
end_marker = '    if !coarse.is_empty() {\n'
i = s.index(start_marker)
j = s.index(end_marker)
assert i < j
loop_block = """    for (variant, per_t) in samples {
        ours_section(&mut text, variant, per_t, args);
    }

"""
s = s[:i] + loop_block + s[j:]

# 3) insert `variant_label` and `ours_section` before `write_report`
anchor = 'fn write_report('
assert anchor in s
helpers = '''fn variant_label(variant: &str) -> &'static str {
    match variant {
        "ours" => "two-base (main construction)",
        "ours-sb" => "single base (Appendix B)",
        "ours-sb-short" => "single base + short role-B exponent",
        _ => "our construction",
    }
}

/// One section of `report.md` per instantiation: the six logical stages, the internal phases,
/// and the fitted `a + b t`.
fn ours_section(
    text: &mut String,
    variant: &str,
    samples: &BTreeMap<usize, ours::Sample>,
    args: &Args,
) {
    let ts: Vec<usize> = samples.keys().copied().collect();
    if ts.is_empty() {
        return;
    }
    let label = variant_label(variant);
    text.push_str(&format!("## {label}: the six logical stages\\n\\n"));
    text.push_str(&format!(
        "Mean over {} repetitions; the total row also shows one standard deviation.\\n\\n",
        args.reps
    ));
    text.push_str("| stage |");
    for t in &ts {
        text.push_str(&format!(" t={t} |"));
    }
    text.push_str("\\n|---|");
    for _ in &ts {
        text.push_str("---:|");
    }
    text.push('\\n');
    for (group, _) in ours::GROUPS {
        text.push_str(&format!("| {group} |"));
        for t in &ts {
            let value = samples[t].per_stage_ms.get(group).copied().unwrap_or(0.0);
            text.push_str(&format!(" {value:.2} |"));
        }
        text.push('\\n');
    }
    text.push_str("| **total** |");
    for t in &ts {
        let summary = Summary::of(&samples[t].total_reps);
        text.push_str(&format!(" **{:.2} ± {:.2}** |", summary.mean, summary.stddev));
    }
    text.push_str("\\n\\n");

    text.push_str(&format!("## {label}: internal phases\\n\\n"));
    text.push_str("| internal phase |");
    for t in &ts {
        text.push_str(&format!(" t={t} |"));
    }
    text.push_str("\\n|---|");
    for _ in &ts {
        text.push_str("---:|");
    }
    text.push('\\n');
    for phase in ours::phase_order() {
        let any = ts
            .iter()
            .any(|t| samples[t].per_phase_ms.get(phase.label()).copied().unwrap_or(0.0) > 0.0);
        if !any {
            continue;
        }
        text.push_str(&format!("| {} |", phase.label()));
        for t in &ts {
            let value = samples[t].per_phase_ms.get(phase.label()).copied().unwrap_or(0.0);
            text.push_str(&format!(" {value:.2} |"));
        }
        text.push('\\n');
    }
    text.push('\\n');

    text.push_str(&format!(
        "### Fitted `a + b t` for {label} (t = number of signers, ms per signer)\\n\\n"
    ));
    text.push_str("| quantity | a (ms) | b (ms / signer) | R^2 |\\n|---|---:|---:|---:|\\n");
    for (name, line) in fits(samples) {
        text.push_str(&format!(
            "| {name} | {:.2} | {:.3} | {:.4} |\\n",
            line.a, line.b, line.r2
        ));
    }
    text.push('\\n');
}

'''
s = s.replace(anchor, helpers + anchor, 1)

open(p, 'w', encoding='utf-8').write(s)
print('write_report patched')
