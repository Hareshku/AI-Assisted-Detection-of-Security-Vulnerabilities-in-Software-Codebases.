from scanner.parser import parse_file
from scanner.analyzer import analyze_file

files = [
    "data/samples/bad_code.py",
    "data/samples/good_code.py",
    "data/samples/pipeline.yml"
]

for filepath in files:
    parse_result = parse_file(filepath)
    if parse_result["status"] != "success":
        continue

    report = analyze_file(parse_result)

    print(f"\n{'='*55}")
    print(f"📄 File     : {report['filepath']}")
    print(f"🔍 Type     : {report['file_type'].upper()}")
    print(f"📊 Violations: {report['total_violations']} "
          f"(🔴 {report['high']} HIGH  "
          f"🟡 {report['medium']} MEDIUM  "
          f"🟢 {report['low']} LOW)")

    print(f"\n   Rule Violations:")
    if report["violations"]:
        for v in report["violations"]:
            emoji = "🔴" if v["severity"] == "HIGH" else \
                    "🟡" if v["severity"] == "MEDIUM" else "🟢"
            print(f"   {emoji} [{v['rule_id']}] {v['name']}")
            print(f"      → {v['description']}")
    else:
        print("   ✅ No violations found")