def run(url, options=None):
    """
    Run real AI-assisted analysis using the LLM integration.

    Defaults to Ollama (local server) if available.
    """
    if options is None:
        options = {}

    # Default to Ollama provider for real integration
    options.setdefault("provider", "ollama")

    from . import llm_integration

    return llm_integration.run(url, options)