[![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
<BR>

<h1>Conceptual Description</h1>
<h2>sign_hash - Takes a directory, hashes files and signs them.<br></h2>
<h2>check_manifest - Takes manifest and public key from a running of sign_hash and checks to see if manifest was tampered<br></h2>
<h2>check_hash - Takes manifest and public key from a running of sign_hash and looks at a directory to both check to see if the files change and also checks if manifest was tampered. <br></h2>

<h1>Why does this exist</h1>
<h2>One of the things that always bothered me is that people provide a list of hashes for a series of files.</h2>
