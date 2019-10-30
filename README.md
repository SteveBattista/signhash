[![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
<BR>

<h1>Conceptual Description</h1>
sign_hash - Takes a directory, hashes files and signs them.<br>
check_manifest - Takes manifest and public key from a running of sign_hash and checks to see if manifest was tampered.<br>
check_hash - Takes manifest and public key from a running of sign_hash and looks at a directory to both check to see if the files changed and also checks if manifest was tampered.<br>

<h1>Why Does This Exist<br></h1>
One of the things that always bothered me is that people provide a list of hashes for a series of files. There is no guarantee that the file of hashes were tampered. With this project one can send the file of hashes, named a manifest and if they keep the public key secure, one can check if the manifest has been tampered. The program does not write out a private key on purpose. This prevents someone from tampering with the file after it has been created. As an added security feature, the file uses its length, its hash and signs this hash, making adjusting the file without rehashing and resigning with the private key detectable.<br>

<h1> How To Use <br></h1>
 Use the flag -h for command line flags <br>

`./sign_hash -d ./place -o manifest234 `<br>
 Take sub-directory named place and all sub directories in it and create a signed hash manifest for them named manifest234
`./check_hash -i manifest234 -o checkfile234 -m` <br>
 Take manifest234 and check to see if it has been tampered. Write results to file named checkfile234<br>
`./check_hash -d ./place -i manifest234 -o checkfile234`<br>
 Take sub-directory named place and see if the hashes and files match the files listed in checkfile234. Take manifest234 and check to see if it has been tampered. Write results to file named checkfile234

<h1> Known Issues/Behaviors/Limitations <br></h1>
 Not following symbolic links:<br>
 Program will not follow infinite loops based on hard links (in Linux). Could add a flag to follow symlinks but this could result in a infinite loop so it is not part of the system.<br><br>

Discussion on nonces:<br>
Nonce length is 128 bytes. This means that after 2^64 number of files, there could be a collision. The program ensures that when creating a manifest file that every file has a unique nonce. It will provide an error message when a collision occurred during construction and pick another random nonce. At orders of magnitude higher than 2^64, one might have delays in picking a nonce. If you are looking at creating a manifest with greater than 2^128 files, the creation program will fail (good luck finishing in your lifetime anyway). When checking the manifest, it checks for duplicated nonces. This makes it very hard to guess the private key from a large manifest. If across all of your manifests you had a line that matched the name, date of last changed, length, nonce which was signed with the same private key, one could substitute one of these lines for the other allowing an attacker to change a file to the one captured in the other manifest. The odds of this are 1/ 2^384 (so low to be impractical with a lifetime of human computing power).<br>

Don't know limits of hashing:<br>
When working on a live linux system /proc/kcore can be very large (e.g. 128TB). Need to see if it can hash a file that big!<br>


<h1>Possible Roadmap <br></h1>
Right now there is only one signing algorithm that is in use. Thinking of adding a post quantum crypto algorithm option.<br>
