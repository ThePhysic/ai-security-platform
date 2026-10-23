def account(request, db):
    return db.accounts[request.args["account_id"]]
