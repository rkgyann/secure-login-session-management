from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5443, debug=False,
            ssl_context=('certs/localhost.crt', 'certs/localhost.key'))
