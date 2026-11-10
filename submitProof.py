
import eth_account
import random
import string
import json
from pathlib import Path
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware  # Necessary for POA chains


def merkle_assignment():
    """
        The only modifications you need to make to this method are to assign
        your "random_leaf_index" and uncomment the last line when you are
        ready to attempt to claim a prime. You will need to complete the
        methods called by this method to generate the proof.
    """
    # Generate the list of primes as integers
    num_of_primes = 8192
    primes = generate_primes(num_of_primes)
    # Create a version of the list of primes in bytes32 format
    leaves = convert_leaves(primes)
    # Build a Merkle tree using the bytes32 leaves as the Merkle tree's leaves
    tree = build_merkle(leaves)

    # Select a random leaf and create a proof for that leaf
    random_leaf_index = random.randrange(1, len(primes))
    proof = prove_merkle(tree, random_leaf_index)
    # This is the same way the grader generates a challenge for sign_challenge()
    challenge = ''.join(
        random.choice(string.ascii_letters)
        for i in range(32)
    )

    addr, sig = sign_challenge(challenge)

    if sign_challenge_verify(challenge, addr, sig):
        tx_hash = send_signed_msg(
            proof, leaves[random_leaf_index]
        )
        print(f"Claim transaction: {tx_hash}")


def generate_primes(num_primes):
    """
        Function to generate the first 'num_primes' prime numbers
        returns list (with length n) of primes (as ints) in ascending order
    """
    primes_list = []
    candidate = 2

    while len(primes_list) < num_primes:
        prime = True

        for divisor in primes_list:
            if divisor * divisor > candidate:
                break
            if candidate % divisor == 0:
                prime = False
                break

        if prime:
            primes_list.append(candidate)

        candidate += 1

    return primes_list


def convert_leaves(primes_list):
    """
        Converts the leaves (primes_list) to bytes32 format
        returns list of primes where list entries are bytes32 encodings of primes_list entries
    """
    return [
        prime.to_bytes(32, byteorder="big")
        for prime in primes_list
    ]


def build_merkle(leaves):
    """
        Function to build a Merkle Tree from the list of prime numbers in bytes32 format
        Returns the Merkle tree (tree) as a list where tree[0] is the list of leaves,
        tree[1] is the parent hashes, and so on until tree[n] which is the root hash
        the root hash produced by the "hash_pair" helper function
    """
    if not leaves:
        return []

    tree = [list(leaves)]

    while len(tree[-1]) > 1:
        current = tree[-1]
        next_level = []

        for i in range(0, len(current), 2):
            sibling = (
                current[i + 1]
                if i + 1 < len(current)
                else current[i]
            )

            next_level.append(
                hash_pair(current[i], sibling)
            )

        tree.append(next_level)

    return tree


def prove_merkle(merkle_tree, random_indx):
    """
        Takes a random_index to create a proof of inclusion for and a complete Merkle tree
        as a list of lists where index 0 is the list of leaves, index 1 is the list of
        parent hash values, up to index -1 which is the list of the root hash.
        returns a proof of inclusion as list of values
    """
    merkle_proof = []

    if (
        not merkle_tree
        or not 0 <= random_indx < len(merkle_tree[0])
    ):
        raise ValueError("Invalid Merkle tree or leaf index")

    index = random_indx

    for level in merkle_tree[:-1]:
        sibling_index = index ^ 1

        if sibling_index >= len(level):
            sibling_index = index

        merkle_proof.append(level[sibling_index])
        index //= 2

    return merkle_proof


def sign_challenge(challenge):
    """
        Takes a challenge (string)
        Returns address, sig
        where address is an ethereum address and sig is a signature (in hex)
        This method is to allow the auto-grader to verify that you have
        claimed a prime
    """
    acct = get_account()

    addr = acct.address
    eth_sk = acct.key

    encoded_challenge = (
        eth_account.messages.encode_defunct(
            text=challenge
        )
    )

    eth_sig_obj = eth_account.Account.sign_message(
        encoded_challenge,
        private_key=eth_sk
    )

    return addr, eth_sig_obj.signature.hex()


def send_signed_msg(proof, random_leaf):
    """
        Takes a Merkle proof of a leaf, and that leaf (in bytes32 format)
        builds signs and sends a transaction claiming that leaf (prime)
        on the contract
    """
    chain = "bsc"

    acct = get_account()
    address, abi = get_contract_info(chain)
    w3 = connect_to(chain)

    if not w3.is_connected():
        raise ConnectionError(
            "Could not connect to BNB Smart Chain testnet"
        )

    contract = w3.eth.contract(
        address=Web3.to_checksum_address(address),
        abi=abi
    )

    already_claimed = (
        contract.functions.getPrimeByOwner(
            acct.address
        ).call()
    )

    if already_claimed != 0:
        print(
            f"This wallet has already claimed "
            f"prime {already_claimed}"
        )
        return None

    prime_int = int.from_bytes(
        random_leaf, byteorder="big"
    )

    owner = contract.functions.getOwnerByPrime(
        prime_int
    ).call()

    if owner != "0x0000000000000000000000000000000000000000":
        raise ValueError(
            f"Prime {prime_int} is already claimed. "
            "Rerun to select a new prime."
        )

    tx_function = contract.functions.submit(
        proof, random_leaf
    )

    tx = tx_function.build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(
            acct.address, "pending"
        ),
        "chainId": w3.eth.chain_id,
        "gasPrice": w3.eth.gas_price,
    })

    tx["gas"] = int(
        w3.eth.estimate_gas(tx) * 1.2
    )

    signed = acct.sign_transaction(tx)

    tx_hash = w3.eth.send_raw_transaction(
        signed.raw_transaction
    )

    receipt = w3.eth.wait_for_transaction_receipt(
        tx_hash, timeout=180
    )

    if receipt.status != 1:
        raise RuntimeError(
            f"Claim transaction failed: {tx_hash.hex()}"
        )

    print(
        f"Successfully claimed prime {prime_int}: "
        f"{tx_hash.hex()}"
    )

    return tx_hash.hex()


# Helper functions

def connect_to(chain):
    if chain not in ["avax", "bsc"]:
        print(f"{chain} is not a valid option")
        return None

    if chain == "avax":
        api_url = (
            "https://api.avax-test.network/ext/bc/C/rpc"
        )
    else:
        api_url = (
            "https://data-seed-prebsc-1-s1.binance.org:8545/"
        )

    w3 = Web3(Web3.HTTPProvider(api_url))

    w3.middleware_onion.inject(
        ExtraDataToPOAMiddleware, layer=0
    )

    return w3


def get_account():
    """
        Returns an account object recovered from the secret key
        in "sk.txt"
    """
    cur_dir = Path(__file__).parent.absolute()

    with open(cur_dir.joinpath("sk.txt"), "r") as f:
        sk = f.readline().rstrip()

    if sk[0:2] == "0x":
        sk = sk[2:]

    return eth_account.Account.from_key(sk)


def get_contract_info(chain):
    """
        Returns a contract address and contract abi from "contract_info.json"
        for the given chain
    """
    contract_file = (
        Path(__file__).parent.absolute()
        / "contract_info.json"
    )

    if not contract_file.is_file():
        contract_file = (
            Path(__file__).parent.parent.parent
            / "tests"
            / "contract_info.json"
        )

    with open(contract_file, "r") as f:
        d = json.load(f)
        d = d[chain]

    return d["address"], d["abi"]


def sign_challenge_verify(challenge, addr, sig):
    """
        Helper to verify signatures, verifies sign_challenge(challenge)
        the same way the grader will. No changes are needed for this method
    """
    eth_encoded_msg = (
        eth_account.messages.encode_defunct(
            text=challenge
        )
    )

    recovered = eth_account.Account.recover_message(
        eth_encoded_msg,
        signature=sig
    )

    if recovered == addr:
        print(
            f"Success: signed the challenge "
            f"{challenge} using address {addr}!"
        )
        return True

    print("Failure: The signature does not verify!")
    print(
        f"signature = {sig}\n"
        f"address = {addr}\n"
        f"challenge = {challenge}"
    )

    return False


def hash_pair(a, b):
    """
        The OpenZeppelin Merkle Tree Validator we use sorts the leaves
        https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/MerkleProof.sol#L217
        So you must sort the leaves as well

        Also, hash functions like keccak are very sensitive to input encoding, so the solidity_keccak function is the function to use

        Another potential gotcha, if you have a prime number (as an int) bytes(prime) will *not* give you the byte representation of the integer prime
        Instead, you must call int.to_bytes(prime,'big').
    """
    if a < b:
        return Web3.solidity_keccak(
            ["bytes32", "bytes32"], [a, b]
        )
    else:
        return Web3.solidity_keccak(
            ["bytes32", "bytes32"], [b, a]
        )


if __name__ == "__main__":
    merkle_assignment()