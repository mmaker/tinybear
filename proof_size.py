import math
import functools

def proof_size_internal(f, batch_size):
    needles = 1472
    # freqs = 2**16 + 2**8 + 2**8
    freqs = 256 * 3

    # without batching, we consider the max
    batch_size = batch_size or freqs
    inverse_needles = needles
    inverse_haystack = freqs
    protocol_commitments = (
        math.ceil(freqs/batch_size) +
        math.ceil(needles/batch_size) +
        math.ceil(inverse_haystack/batch_size) +
        math.ceil(inverse_needles/batch_size)
    )
    # 2 multivariate openings at sumcheck_challenges and twist
    batch_open_proof = 2 * f(batch_size)

    return (
        # commitments and evaluations
        protocol_commitments * 2 +
        # sumcheck size
        11 * 2 +
        # openings
        batch_open_proof
    )



algs = {
    'bp': functools.partial(proof_size_internal,  lambda x: math.ceil(math.log2(x))),
    'fri': functools.partial(proof_size_internal, lambda x: math.ceil(math.log2(x))**2),
    '𝛴-prot': functools.partial(proof_size_internal, lambda x: x),
    'kzg': functools.partial(proof_size_internal, lambda x: 1)
}

if __name__ == "__main__":
    for (alg, estimator) in algs.items():
        for b in [None, 64, 128, 256, 512, 1024, 1144, 2048, 4096]:
            b_proof_bytes = (estimator(b) * 32) * 1e-3
            print(f"{alg}\t{b_proof_bytes:.2f}KB" + (f" (batch size {b})" if b else ""))