from pathlib import Path
import yaml

neo_url = 'bolt://localhost:7687'

def get():
    filename = Path(__file__).parent.parent.parent / \
        'db' / 'docker-compose.yml'
    with filename.open() as fp:
        return yaml.load(fp, Loader=yaml.FullLoader)
