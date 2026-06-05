#Correr el Proyecto
git clone https://github.com/tuusuario/ouroboros-ids.git
cd ouroboros-ids
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
