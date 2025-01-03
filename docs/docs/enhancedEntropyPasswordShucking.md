---
uid: enhancedEntropyPasswordShucking
---

# Password Shucking in Enhanced Entropy V2 (PassLib style)

Taken from <https://github.com/BcryptNet/bcrypt.net/issues/110>

---

## Preface

I'd start off by stating that I believe the "risk" is over-egged; it's just another entry alongside other breach-correlation-attacks.
The feature was implemented to match the spec of other programming languages rather than as a magic bullet.
Offline credential stuffing is pay-dirt; its why people feed on breach data; password-reuse is rife.

The tldr of what the issue is;  if you can tell that a password is sha512(password) in a bcrypt hash by validating the hash then you can just crack the hash;
while using a normal bcrypt call would produce a hash based on the password alone; meaning you'd have to crack a whole lot of correlated data to get the same level of matches.
It's not without merit; but it isn't quite the end of the world.

Remember; bcrypt/argon etc aren't magically making data super secure; they're just making it much harder for someone with an offline copy of your data to get at the passwords which they could then reuse elsewhere.

## The Issue

But lets go over how shucking works without the song and dance and drama.

--

* Site1 hashes passwords as md5(pass). They get breached, hashes dumped on the net.
* Site2 hashes passwords as bcrypt(md5(pass)). They get breached, hashes dumped on the net.

Using a bit of querying you'd find all the matches between the two sets of users (match on email / name whatever)
Then using bcrypt yourself locally you would test some of the passwords against the matching hashes (you can usually work out what generated a hash)

`bcrypt(site-1-md5, salt(from site2))`

If you have a match you can concentrate on cracking the fast hashes instead that you got from `site1` and quickly make pay from people's **password reuse**.

* **Now I've highlighted password reuse because that's the main issue here. Hence it falls into breach-correlation-attacks.**
* **You wouldn't be "shucking" off bcrypt; if `site 1` stored all passwords in plaintext you could pump those against bcrypt verify against site 2 (though you'd be quicker using site 2's Api normally and let them pay the electric)**
* **The risk is pretty much the same as any reuse situation; its just a different attack vector.**

If a user re-uses passwords and a single site gets breached holding the data in a HASH they can correlate the data and crack the easier of the two.

* You still require both data sources
* You have to either have prior knowledge of the pre hashing or test a variety using a variety of correlated data to work out if its being pre-hashed
* This is mostly about offline cracking with multiple data-sources and finding workarounds to reduce cracking time.
* You could still filter correlated hashes from Site1 and crack those the old fashioned way then spray-and-pray them against thousands of other sites (which is what happens after most major breaches)

---

Security is always about balance; the "enhanced-entropy" option simply allows you to retain entropy beyond the normal limits of bcrypt
so people using a "pass phrases / memorable passwords" like `horse battery staple everyone loves xkcd because there are quite literally every situation covered in those weird commits`
don't have their miraculous willingness to type stuff wasted by truncation. We retain the entropy through hashing.

It's not really an "extra feature" and I'd argue (and do whenever given the chance) that it's not really increasing the risk, as security should **always be handled in layers and at depth**.

For me a better solution would be something like

```text
bcrypt(hmacsha384(string + kmsdecrypt(pepper)))
```

or to split it out slightly based on an AWS flavour

```text
User Set Password Request <Password>
Service checks passwords meet complexity requirements [reject if not met]
> Service has been started with Microsoft data protection API loaded; keys have been generated either in-place or rotation can be handled externally or sidecar.
> DPA keys are generated and stored; but key material is protected by kms (service access to kms restricted by IAM)
Service decrypts the pepper and appends to password during HMAC step
Service BCrypts the HMAC
Stores
```

You're essentially altering the password in this setup to PASS + Pepper; pepper doesn't need to be a single value; you could use the DPA to encrypt the password passed in with what DPA calls a `Purpose`
essentially providing extra key material for encryption something like the user-id (just an example).

Your password would then be `bcrypt(hmacsha384(dpa-encrypt(password)))`

With the salt of course generated randomly.

Alternatively you could swap it around and simply

`dpa-encrypt(bcrypt(hmacsha384(password)))`

Which is how Enhanced-Entropy V3 works.

Layering security as in order to break the password at this point you'd need to have

* The database in order to do anything (you're not going to guess the implementation by shucking)
* The code and implementation to work out how its being handled, and how `purposes` are being set
* Access to the key material generated by DPA
* Access to the Vault/KMS used to protect the key-material file.

![image](https://media.giphy.com/media/22eVpVYpRhaE0/giphy.gif)

Or on the simpler end swapping SHA512 for the same hash with a HMAC set using your pepper, as suggested by the "[king of password cracking rigs](https://www.youtube.com/watch?v=4Ell1Tt23NI)" [J.Gosney](https://www.linkedin.com/in/jgosney/).

---

References:

* <https://docs.microsoft.com/en-us/aspnet/core/security/data-protection/introduction?view=aspnetcore-6.0>
* <https://docs.microsoft.com/en-us/aspnet/core/security/data-protection/implementation/authenticated-encryption-details?view=aspnetcore-6.0>
* <https://docs.microsoft.com/en-us/aspnet/core/security/data-protection/implementation/key-encryption-at-rest?view=aspnetcore-6.0>
* <https://security.stackexchange.com/questions/234794/is-bcryptstrtolowerhexmd5pass-ok-for-storing-passwords/234795#234795>  (ignore the null byte bit as that's not valid in this lib, we have the tests to prove it)
* <https://twitter.com/jmgosney/status/1286685310961750018>
* The shucking talk <https://youtu.be/OQD3qDYMyYQ> (breach correlation overview <https://youtu.be/OQD3qDYMyYQ?t=1193>) (shucking in stuffing <https://youtu.be/OQD3qDYMyYQ?t=1406>)

![image](https://user-images.githubusercontent.com/83597/169357838-f5cefb07-48c2-42b6-be68-747a6ad2b2c4.png)

## Other references

Other references if you're really bored that I've just nicked off someone else's list
but are good for understanding how the majority of people behave with passwords.

**Contraindications of Password Expiration**

* Academia, NIST (USA), NCSC (UK)

Some recent research and comments on the negative consequences of enforcing password expiration
2010 - Where Do Security Policies Come From?
<https://cups.cs.cmu.edu/soups/2010/proceedings/a10_florencio.pdf>

2010 - The True Cost of Unusable Password Policies: Password Use in the Wild
<https://www.cl.cam.ac.uk/~rja14/shb10/angela2.pdf>

2010 - The Security of Modern Password Expiration: An Algorithmic Framework and Empirical Analysis
<http://cs.unc.edu/~fabian/papers/PasswordExpire.pdf>

2014 - United States Federal Employees’ Password Management Behaviours – A Department of Commerce Case Study
<https://nvlpubs.nist.gov/nistpubs/ir/2014/NIST.IR.7991.pdf>

2015 - Quantifying the Security Advantage of Password Expiration Policies
<http://people.scs.carleton.ca/~paulv/papers/expiration-authorcopy.pdf>

2015 - Why we hate IT: Two surveys on pre‐generated and expiring passwords in an academic setting
<https://onlinelibrary.wiley.com/doi/epdf/10.1002/sec.1184>

2016 - The Problems with Forcing Regular Password Expiry
<https://www.ncsc.gov.uk/blog-post/problems-forcing-regular-password-expiry>

2016 - Time to rethink mandatory password changes
<https://www.ftc.gov/news-events/blogs/techftc/2016/03/time-rethink-mandatory-password-changes>

2016 - Revisiting Password Rules: Facilitating Human Management of Passwords
<http://people.scs.carleton.ca/~paulv/papers/eCrime2016pwdrules.pdf>

2018 - User Behaviours and Attitudes Under Password Expiration Policies
<https://www.usenix.org/system/files/conference/soups2018/soups2018-habib-password.pdf>

Some related sources showing that users will change their passwords in very predictable ways

2014 - The Tangled Web of Password Reuse
<http://www.jbonneau.com/doc/DBCBW14-NDSS-tangled_web.pdf>

2016 - Targeted Online Password Guessing: An Underestimated Threat
<http://wangdingg.weebly.com/uploads/2/0/3/6/20366987/ccs16_final_v12.pdf>

2016 - Understanding Password Choices: How Frequently Entered Passwords Are Re-used across Websites
<https://www.usenix.org/system/files/conference/soups2016/soups2016-paper-wash.pdf>

2018 - “What was that site doing with my Facebook password?” Designing Password-Reuse Notifications

2018 - Abusing Password Reuse at Scale: BCrypt and Beyond
<https://www.youtube.com/watch?v=5su3_Py8iMQ>

2018 - Shadow Attacks Based on Password Reuses: A Quantitative Empirical Analysis
<http://faculty.cs.tamu.edu/guofei/paper/PasswordReuse-TDSC.pdf>

2019 - Beyond Credential Stuffing: Password Similarity Models using Neural Networks
<https://www.cs.cornell.edu/~rahul/papers/ppsm.pdf>
