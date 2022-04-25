# cripter
Encryption functions for Godot Engine.


## Instructions:
Download or clone the repository to your computer. Copy the cripter folder into the Godot module folder and compile.
It's expected this module will be compiled in both Godot 3 and Godot 4 without problems. It can detect Godot's version and will do the job. 
It is expected that this module can be compiled on all platforms that Godot supports.

There are two examples of identical projects. One for Godot 3 and one for Godot 4. They are in the folders "Cripter_Exemple_GD". 

This module offers encryption using the algorithms: GCM, CBC and RSA. The RSA algorithm is the only one that needs an SSH key pair.
The example projects has a pair of keys that you can use in your tests.
DO NOT use the keys in this demo for your project. This is unsafe. Generate your own keys.


#### To generate an RSA key pair on linux use this commands lines:

Generate the private key:

openssl genrsa -out rsa_private_key.pem -aes256 4096

Generate the public key:

openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem


# Disclaimer

> THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
