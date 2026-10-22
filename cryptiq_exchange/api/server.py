"""Server launcher for the CRYPTIQ REST API."""

import argparse
import uvicorn

from .app import create_app


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Launch CRYPTIQ REST API server."
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind the server to (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind the server to (default: 8000)",
    )
    parser.add_argument(
        "--raw-dir",
        default=None,
        help="Path to directory containing verified tagpack YAML files.",
    )
    parser.add_argument(
        "--investigations-dir",
        default="data/processed/investigations",
        help="Directory to save/load case reports (default: data/processed/investigations)",
    )

    args = parser.parse_args()

    app_instance = create_app(
        raw_dir=args.raw_dir,
        investigations_dir=args.investigations_dir,
    )

    print(f"Starting CRYPTIQ REST API on http://{args.host}:{args.port}")
    print(f"Interactive OpenAPI Documentation: http://{args.host}:{args.port}/docs")
    uvicorn.run(app_instance, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
