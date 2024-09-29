### SLH-DSA
This is a python implementation of SLH-DSA according to FIPS-205 published on August 2024.

#### main function API:
        slh_keyGen, slh_sign, slh_verify
        slh_keyGen_internal, slh_sign_internal, slh_verify_internal

#### The standard SLH-DSA can be created by:
        SLH_DSA.SLH_DSA_SHA2_128f(),  
        SLH_DSA.SLH_DSA_SHA2_128s(),
        SLH_DSA.SLH_DSA_SHA2_192f(), 
        ...


#### use case:
    M = os.urandom(3)
    ctx = b''
    case = SLH_DSA.SLH_DSA_SHA2_128f()
    sk, pk = case.slh_keygen()
    sig = case.hash_slh_sign(M, ctx, "sha-256", sk)
    print(case.hash_slh_verify(M, sig, ctx, "sha-256", pk))