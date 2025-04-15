import re
import os

def parse_thrift(file_path):
    with open(file_path, 'r') as f:
        content = f.read()

    # Remove comments starting with "//"
    content = re.sub(r'//.*$', '', content, flags=re.MULTILINE)

    # Extract namespace
    namespace_match = re.search(r'namespace\s+\w+\s+(\w+)', content)
    namespace = namespace_match.group(1) if namespace_match else None

    # Extract services and methods
    services = {}
    service_matches = re.finditer(r'service\s+(\w+)\s*{([^}]*)}', content, re.DOTALL)
    for service_match in service_matches:
        service_name = service_match.group(1)
        service_body = service_match.group(2)
        methods = {}
        method_matches = re.finditer(r'(\w+)\s+(\w+)\s*\([^)]*\)\s*(?:\(([^)]*)\))?', service_body)
        for method_match in method_matches:
            return_type = method_match.group(1)
            method_name = method_match.group(2)
            annotations = method_match.group(3)
            methods[method_name] = {
                "return_type": return_type,
                "annotations": parse_annotations(annotations) if annotations else {}
            }
        services['.'.join([namespace, service_name])] = methods

    return {
        "services": services
    }

def parse_annotations(annotation_str):
    annotations = {}
    annotation_matches = re.finditer(r'(\w+)\s*=\s*"([^"]*)"', annotation_str)
    for match in annotation_matches:
        annotations[match.group(1)] = match.group(2)
    return annotations

# Example usage
if __name__ == "__main__":
    file_path = os.path.join(os.path.dirname(__file__), "../PotatoService.thrift")
    parsed_data = parse_thrift(file_path)
    print(parsed_data)
