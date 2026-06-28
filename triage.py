from logtriage.cli import get_args
from logtriage.pipeline import run_pipeline

def main():
    args = get_args()
    run_pipeline(args)

if __name__ == "__main__":
    main()
