import argparse


def main():
    parser = argparse.ArgumentParser(
        description="DuressAuth CLI - Coercion-resistant authentication system"
    )

    parser.add_argument(
        "command",
        choices=["register", "login"],
        help="Command to execute"
    )

    args = parser.parse_args()

    if args.command == "register":
        print("Register flow not implemented yet.")
    elif args.command == "login":
        print("Login flow not implemented yet.")


if __name__ == "__main__":
    main()
