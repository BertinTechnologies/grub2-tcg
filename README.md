# OpenDTeX GRUB2 Trusted Computing Group support

## Project Description

The OpenDTeX research project aims at providing trusted building
blocks to ensure **strong security properties during the boot chain**
and to allow **secure execution of isolated enclaves** on x86
architectures.

OpenDTeX has been achieved with the help of the French “`RAPID
<http://www.ixarm.com/Projets-d-innovation-duale-RAPID>`_” grant
process, which targets both civil and defense use cases, through a
consortium composed of AMOSSYS, Bertin Technologies and Telecom
ParisTech.

This project leverages **TCG** technologies, such as **TPM** and
**DRTM**, to provide trusted execution of a minimal TCB (Trusted
Computing Base). Besides, each building block can display proof of
integrity up to the platform user, by implementing the concept of
trusted banner, thus creating a trusted path between the user and the
TCB.

The results of this project have been integrated in a Linux-based
prototype, as well as in the PolyXene multi-level security operating
system.

We provide here the implementation of the GRUB2 TCG SRTM component.

See Secure Boot component in DRTM mode here :
* [OpenDTeX-Secure-Boot-DRTM](https://github.com/AMOSSYS/OpenDTeX-Secure-Boot-DRTM)


## Authors and Sponsors

See the top distribution file ``AUTHORS-TCG.txt`` for the detailed and updated list
of authors.

Project sponsors:

* [AMOSSYS](http://www.amossys.fr)
* [Bertin Technologies](http://www.bertin.fr)
* [Telecom ParisTech](https://www.telecom-paristech.fr)


## License

This software is licensed under the GPL v3. See the
``COPYING.txt`` file for the full license text.


## More Information

| &nbsp;   | &nbsp; |
| ------   | -----  |
| Website  | [https://github.com/BertinTechnologies/grub2-tcg](https://github.com/BertinTechnologies/grub2-tcg) |
| Email    | erwan.ledisez@bertin.fr |


## OpenDTeX developments

OpenDTeX work notably include:

* A TPM 1.2 API library independent from the BIOS or OS
* A minimal TSS API library independent from the OS
* A set of tools to manipulate the TPM.
* An extension of Grub 2 (i.e. an SRTM implementation)
* The implementation of a dedicated DRTM MLE extension (based on Trusted Boot)


## Comparison with similar tools

* **Trusted Grub**: this tool permits to extend the trust chain
  by measuring components that are executed beyond the BIOS, in SRTM mode.
* **Trusted Boot**: this tool permits to start a new trust chain, in DRTM
  mode. Is also permits to verify the integrity of the Linux kernel
  and its associated initrd.
* **Bitlocker** (in TPM mode): this tools allows to seal the master key
  with the TPM so that decryption is possible only if the platform
  integrity is correct. It only works through a SRTM (which means a large
  TCB).
* **Anti-Evil-Maid** proof of concept from Joanna Rutkowska, which
  implements the concept of secure banner. This PoC only supports
  SRTM.

OpenDTeX Secure Boot allows both integrity verification and unsealing
of boot time components, either in SRTM or DRTM mode. Besides, it
provides explicit trust attestation to the user thanks to a shared
secret (the secret banner).

## GRUB2 architecture

To complete.

## GRUB2 compilation

```
$ ./autogen.sh
$ ./configure --enable-tcg
$ make
$ sudo make install
```


## Acknowledgment

We would like to thanks people behind the following projects:

* GRUB2: [http://www.gnu.org/software/grub/index.html](http://www.gnu.org/software/grub/index.html)
* Intel Trusted Boot: [http://sourceforge.net/projects/tboot/](http://sourceforge.net/projects/tboot/)
* Flicker: [http://sourceforge.net/projects/flickertcb/](http://sourceforge.net/projects/flickertcb/)
