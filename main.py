
#import rsa file to use its functions
import rsa
def main():
    #Generate a public and private key pair for Alice
    p, q = rsa.generate_primes(512)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = rsa.find_public_key(phi_n)
    d = rsa.find_private_key(e, phi_n)
    alice_public_key = (n, e)
    alice_private_key = (n, d)
    # Generate a public and private key pair for Bob
    p, q = rsa.generate_primes(512)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = rsa.find_public_key(phi_n)
    d = rsa.find_private_key(e, phi_n)
    bob_public_key = (n, e)
    bob_private_key = (n, d)
    print("-----------")

    # Alice wants to send a message to Bob
    message = "Hello, Bob!"

    # Alice encrypts the message using Bob's public key
    ciphertext = rsa.encrypt_message(message, bob_public_key)

    # Bob decrypts the message using his private key
    decrypted_message = rsa.decrypt_message(ciphertext, bob_private_key)
    print("-----------")

    # Bob sends a reply to Alice
    reply = "Hi, Alice!"

    # Bob signs the reply using his private key
    signature = rsa.sign_message(reply, bob_private_key)

    # Alice receives the reply and verifies the signature using Bob's public key
    is_valid_signature = rsa.verify_signature(reply, signature, bob_public_key)


    # Print the results
    print("Alice's public key:", alice_public_key)
    print(
        "--------------------------------------------------------------------------------------------------------------------------")
    print("Alice's private key:", alice_private_key)
    print(
        "--------------------------------------------------------------------------------------------------------------------------")

    print("Bob's public key:", bob_public_key)
    print(
        "--------------------------------------------------------------------------------------------------------------------------")

    print("Bob's private key:", bob_private_key)
    print(
        "--------------------------------------------------------------------------------------------------------------------------")
    print(
        "-------------------------------------Communication------------------------------------------------------------------------")

    print("Message from Alice to Bob:", message)
    print("Encrypted message:", ciphertext)
    print("Decrypted message by Bob:", decrypted_message)
    print(
        "-------------------------------------Sign & verify------------------------------------------------------------------------")
    print("Reply from Bob to Alice:", reply)
    print("Digital signature by Bob:", signature)
    print("Is the signature valid?", is_valid_signature)


if __name__ == '__main__':
    main()


