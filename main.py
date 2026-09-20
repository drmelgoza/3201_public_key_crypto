import string
from model import Model
from bad_actor import BadActor

def main():
    #set up models for Alice and Bob
    alice = Model()
    bob = Model()
    #Set up bad actor model for Mallory
    #mallory for part 2
    mallory = BadActor()

    #init initial q and alpha values
    q = int.from_bytes(bytes.fromhex("""B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6
       9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0
       13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70
       98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0
       A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708
       DF1FB2BC 2E4A4371"""))

    alpha = int.from_bytes(bytes.fromhex("""A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F
       D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213
       160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1
       909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A
       D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24
       855E6EEB 22B3B2E5"""))

    #set and distribute q and alpha values
    alice.set_q_and_a(q, alpha)
    alice.send_q_and_a(bob)

    #following line for part 2
    #mallory steals q and a values
    mallory.steal_q_and_a(alice)
    #following line for 2.2
    #mallory alters the others' q value
    mallory.alter_a([bob, alice], q)

    #alice and bob set there partial secret values
    alice.set_partial_secret()
    bob.set_partial_secret()

    #alice and bob send their partial values to each other
    alice.send_partial_s(bob)
    #following mallory function call for 2.1
    #mallory intercepts the value, sending bob the incorrect value
    #mallory.intercept(bob)
    bob.send_partial_s(alice)
    #following mallory function call for 2.1
    # mallory intercepts the value, sending alice the incorrect value
    #mallory.intercept(alice)

    #Alice and bob set their encryption keys.
    alice.set_secret_number()
    bob.set_secret_number()

    alice.set_key()
    bob.set_key()

    print(f"alice's key: {alice.get_key()}")
    print(f"bob's key: {bob.get_key()}\n")

    #alice and bob set a shared iv value
    alice.set_and_share_iv(bob)

    #following line for part 2
    #mallory steals the iv value to use it as well.
    mallory.steal_iv(alice)

    #send messages
    alice.send_message("Hi Bob!", bob)
    bob.send_message("Hi Alice!", alice)

    print(f"alice's received message: {alice.get_partner_message()}")
    print(f"bob's received message: {bob.get_partner_message()}\n")
    print(f"alice's received message reads: \n\t{alice.decrypt_message()}")
    print(f"bob's received message reads: \n\t{bob.decrypt_message()}")

    #following 2 lines for part 2
    #mallory decrypts the messages due to her alterations.
    print(f"mallory got alice's message!\nalice's message reads: \n\t{mallory.steal_and_decrypt_msg(alice)}")
    print(f"mallory got bob's message!\nbob's message reads: \n\t{mallory.steal_and_decrypt_msg(bob)}")


if __name__ == '__main__':
    main()
