

def hash_password(password, salt=None):
    # generate salt if not provided
    if salt is None:
        salt = generate_salt()

    # fill to 16 chars if too short
    if len(salt) < 16:
        salt += ("a" * (16 - len(salt)))

    # cut to 16 if too long
    if len(salt) > 16:
        salt = salt[:16]

    # use sha256 algorithm to generate haintegersh
    t_sha = hashlib.sha256()

    # we have to encode salt & password to utf-8, this is required by the
    # hashlib library.
    t_sha.update(salt.encode('utf-8') + password.encode('utf-8'))

    # return salt & hash joined
    return salt + t_sha.hexdigest()


def check_password(pass_to_check, hashed):
    # extract salt
    salt = hashed[:16]

    # extract hash to compare with
    hash_to_check = hashed[16:]

    # hash password with extracted salt
    new_hash = hash_password(pass_to_check, salt)

    # compare hashes. If equal, return True
    return new_hash[16:] == hash_to_check


def generate_salt():
    salt = ""
    for i in range(0, 16):
        # get a random element from the iterable
        salt += random.choice(ALPHABET)
    return salt
