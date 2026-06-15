from scanner.parser import parse_file
import ast
files = [
    "data/samples/bad_code.py",
    "data/samples/good_code.py",
    "data/samples/pipeline.yml"
]

for filepath in files:
    result = parse_file(filepath)
    print(f"\n{'='*50}")
    print(f"File     : {result['filepath']}")
    print(f"Type     : {result.get('file_type', 'unknown')}")
    print(f"Status   : {result['status']}")

    if result["status"] == "success":
        if result["file_type"] == "python":
            # Count how many nodes are in the AST
            node_count = sum(1 for _ in ast.walk(result["ast_tree"]))
            print(f"AST Nodes: {node_count}")
        elif result["file_type"] == "pipeline":
            print(f"Stages   : {len(result['stages'])}")
            for stage in result["stages"]:
                print(f"  → {stage['stage']}: {len(stage['commands'])} commands")
    else:
        print(f"Error    : {result['error']}")