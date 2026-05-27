import argparse
import asyncio
import sys
from fastmcp import Client

def parse_kv_pairs(pairs):
    """
    Parses trailing command-line arguments in key=value format into a dictionary.
    """
    result = {}
    if not pairs:
        return result
    for pair in pairs:
        if '=' not in pair:
            print(f"[-] Invalid parameter format: '{pair}'. Expected key=value.")
            sys.exit(1)
        key, value = pair.split('=', 1)
        result[key] = value
    return result

# 1. Set up the argument parser
parser = argparse.ArgumentParser(
    description="MCP Capability Wrapper - Invoke tools, resources, templates, and prompts from the CLI.",
    formatter_class=argparse.RawTextHelpFormatter,
    epilog="""Examples:
  tool:      python3 mcp_invoke.py http://172.17.0.2:8000/mcp/ tool execute_server_command command="id"
  resource:  python3 mcp_invoke.py http://172.17.0.2:8000/mcp/ resource resource://logs
  template:  python3 mcp_invoke.py http://172.17.0.2:8000/mcp/ template quantity://{item} item="banana"
  prompt:    python3 mcp_invoke.py http://172.17.0.2:8000/mcp/ prompt spell_check text="Hllo"
"""
)

parser.add_argument("server_url", help="Target MCP server URL")
parser.add_argument("type", choices=["tool", "resource", "template", "prompt"], help="The type of capability to invoke")
parser.add_argument("name", help="The name, URI, or URI template of the target capability")
parser.add_argument("params", nargs="*", help="Optional parameters passed as key=value pairs (e.g., param1=value1 param2=value2)")

# Print help text and exit if no arguments are provided
if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

args = parser.parse_args()
parameters = parse_kv_pairs(args.params)

# 2. Initialize the client
client = Client(args.server_url)

async def main():
    async with client:
        print(f"[*] Sending payload to {args.type.upper()}: '{args.name}'...")
        if parameters:
            print(f"[*] With parameters: {parameters}")
        print("-" * 60)

        try:
            # --- TOOL EXECUTION ---
            if args.type == "tool":
                result = await client.call_tool(args.name, parameters)
                # Handle FastMCP tool result structure (often contains a content array)
                if hasattr(result, "content") and result.content:
                    for element in result.content:
                        print(element.text if hasattr(element, "text") else element)
                else:
                    print(result)

            # --- FIXED RESOURCE READING ---
            elif args.type == "resource":
                result = await client.read_resource(args.name)
                # Resources usually return a list of content objects
                if isinstance(result, list):
                    for element in result:
                        print(element.text if hasattr(element, "text") else element)
                else:
                    print(result)

            # --- RESOURCE TEMPLATE READING ---
            elif args.type == "template":
                # Construct the final URI by substituting the template placeholders
                # e.g., "quantity://{item}" formatted with {"item": "banana"} -> "quantity://banana"
                try:
                    final_uri = args.name.format(**parameters)
                    print(f"[*] Resolved Template URI: {final_uri}\n")
                except KeyError as e:
                    print(f"[-] Missing required template parameter: {e}")
                    sys.exit(1)

                result = await client.read_resource(final_uri)
                if isinstance(result, list):
                    for element in result:
                        print(element.text if hasattr(element, "text") else element)
                else:
                    print(result)

            # --- PROMPT RETRIEVAL ---
            elif args.type == "prompt":
                result = await client.get_prompt(args.name, parameters)
                print(result)

        except Exception as e:
            # Centralized exception catching to safely capture and display verbose server errors
            print(f"[-] Error executing capability:")
            print(f"{str(e)}")

if __name__ == "__main__":
    asyncio.run(main())
