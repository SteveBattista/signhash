[![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
<BR>

<h1>Conceptual Description</h1>
<h2>sign_hash - Takes a directory, hashes files and signs them.<br></h2>
<h2>check_manifest - Takes manifest and public key from a running of sign_hash and checks to see if manifest was tampered.<br></h2>
<h2>check_hash - Takes manifest and public key from a running of sign_hash and looks at a directory to both check to see if the files changed and also checks if manifest was tampered.<br></h2>

<h1>Why does this exist<br></h1>
<h2>One of the things that always bothered me is that people provide a list of hashes for a series of files. There is no guarantee that the file of hashes were tampered. With these programs one can send the file of hashes, named a manifest and if they keep the public key secure, one can check if the manifest has been tampered.<br></h2>

<h1> How to use <br></h1>
<h2> Use the flag -h for command line flags <br><h2>

<h1> Known issues <br></h1>
<h2> While program will not follow infinite loops based on hard links (in Linux), if a broken hard link exists, the program will exit and not finish its work. <br></h2>
<h2> Spelling. I need to clean up all of the text and spell check it.<br></h2>

<h1>Possible roadmap<br></h1>
<h2>Right now there is only one signing algorithm that is in use. Thinking of adding a post quantum crypto algorithm option<br></h2>
