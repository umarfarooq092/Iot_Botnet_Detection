from app.config import get_settings

def main():
    s = get_settings()
    print('ENV:' + s.environment)
    print('DBKEYLEN:' + str(len(s.db_encryption_key)))

if __name__ == '__main__':
    main()
