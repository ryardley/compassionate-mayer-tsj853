# Engineering Challenge
## Enclave

In two hours or less, fork this codesandbox and attempt to:
1. debug the program so that the results match.
2. refactor the code, breaking stages into modular functions.
3. allow users to pass in an arbitrary array of values, rather than the current hardcoded values.
4. [stretch goal] generate proofs that ciphertext inputs are valid.
    1. Use [Circom’s web compiler](https://zkrepl.dev/) to generate circuits that can prove the following:
    2. Create a circuit that proves that a private integer input is within the range of [0, 100].
    3. Create a circuit that proves that a private integer input belongs to an array of public integers from 0 to 100.
    4. Create a circuit that proves that a private integer input is the Poseidon preimage of the hash output.

You can choose to address any or all of the above points in whatever order you find most interesting.

We want to be respectful of your time, please don't spend more than 2 hours on this project. It is ok for your solution to be broken and/or incomplete. Your output will be used as a prompt for the technical interview.

Please share your fork of the codesandbox and or github gists in a reply email to hiring@gnosisguild.org.