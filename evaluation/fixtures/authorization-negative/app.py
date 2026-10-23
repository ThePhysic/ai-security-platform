def account(request, db):
    row = db.accounts[request.args["account_id"]]
    if row.owner_id != request.user.id:
        raise PermissionError()
    return row
