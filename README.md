# cripter
Encryption functions for Godot Engine.

### Instructions:
Download or clone the repository to your computer. Copy the folder cripter into the Godot module folder and compile.
The cripter_project folder contains a basic project accompanied by a pair of keys and instructions for generating them.
Do not use the keys in this demo for your project. This is unsafe. Generate your own keys.

To generate RSA keys on linux use this command line to generate the private key:
ssh-keygen -t rsa -b 4096 -C "cripter_exemple"

and this command line to generate the public key
ssh-keygen -f id_rsa.pub -m 'PEM' -e > id_rsa.pem

#### Check the sample project for more usage information.

The same process can be done on Windows and macOS.


# Disclaimer

> THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
