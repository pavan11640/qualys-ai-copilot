"""LLM client compatibility shim.

This project uses Amazon Bedrock exclusively.
All AI invocations route through src.bedrock_client.BedrockClient.
"""

from src.bedrock_client import BedrockClient

__all__ = ["BedrockClient"]
