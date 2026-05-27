import argparse
import asyncio
import sys
from fastmcp import Client

# 1. Set up the argument parser to handle CLI inputs and help text
parser = argparse.ArgumentParser(
    description="Enumerate resources, templates, tools, and prompts from an MCP server.",
    formatter_class=argparse.RawTextHelpFormatter
)
parser.add_argument(
    "server_url",
    help="The target MCP server URL (e.g., 'http://172.17.0.2:8000/mcp/')"
)

# If no arguments are provided, print the help text and exit
if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

args = parser.parse_args()

# 2. Initialize the client with the provided CLI argument
client = Client(args.server_url)

async def main():
    async with client:
        # Fetch all available server primitives
        resources = await client.list_resources()
        resource_templates = await client.list_resource_templates()
        tools = await client.list_tools()
        prompts = await client.list_prompts()  # Added to enumerate prompts

        print(f"[*] Enumerating MCP Server: {args.server_url}\n")

        # --- Resources ---
        print("-" * 75)
        print("| Resources |")
        print("-------------")
        for resource in resources:
            print(f"Name: {resource.name}")
            print(f"URI:  {resource.uri}")
            print(f"Description: {resource.description.strip()}" if resource.description else "No description")
            print("-" * 50)

        # --- Resource Templates ---
        print()
        print("-" * 75)
        print("| Resource Templates |")
        print("----------------------")
        for resource_template in resource_templates:
            print(f"URI Template: {resource_template.uriTemplate}")
            print(f"Description: {resource_template.description.strip()}" if resource_template.description else "No description")
            print("-" * 50)

        # --- Tools ---
        print()
        print("-" * 75)
        print("| Tools |")
        print("---------")
        for tool in tools:
            params = list(tool.inputSchema.get('properties', {}).keys())
            print(f"{tool.name}({', '.join(params)})")
            print(f"Description: {tool.description.strip()}" if tool.description else "No description")
            print("-" * 50)

        # --- Prompts ---
        print()
        print("-" * 75)
        print("| Prompts |")
        print("-----------")
        for prompt in prompts:
            # Extract arguments if the prompt template requires them
            prompt_args = [arg.name for arg in prompt.arguments] if prompt.arguments else []
            print(f"{prompt.name} (Arguments: {', '.join(prompt_args) if prompt_args else 'None'})")
            print(f"Description: {prompt.description.strip()}" if prompt.description else "No description")
            print("-" * 50)

if __name__ == "__main__":
    asyncio.run(main())
