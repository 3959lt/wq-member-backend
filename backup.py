import sqlite3,datetime,pathlib
base=pathlib.Path('/var/lib/wq-backend')
name=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
with sqlite3.connect(str(base/'app.sqlite3')) as src,sqlite3.connect(str(base/'backups'/f'{name}.sqlite3')) as dst: src.backup(dst)
files=sorted((base/'backups').glob('*.sqlite3'))
for path in files[:-7]: path.unlink()
