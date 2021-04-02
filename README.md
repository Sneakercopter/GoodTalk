# Good Talk
API Communication when Client to Server and Server to Client message integrity cannot be trusted.

## Description
This repository serves as a proof of concept implementation of a proposed protocol to validate the integrity of messages sent to servers from the client and also vice versa. The benefit of this is to allow for the detection of modified or tampered packets in both the request and response body which will stop trivial packet edits and attacks from MITM packet analysis tools such as [Charles](https://www.charlesproxy.com/) or [Fiddler](https://www.telerik.com/fiddler).

## Example Implementation
The implementation presented here uses a Python HTTP server and client implementation to demonstrate the signature and integrity validation process. The concepts presented in this example are not limited to this application and can be applied across any language and protocol.

## Example Server
An example server running the server code from this repository is available at ```https://api.sneakercopter.io/authenticate```. You can use the client example within this repository to connect and test the protocol using this URL **NOTE: This example server is rate limited and will restrict your access if request frequency is too high, so please play nice!**

## Valid Keys for Example Server 
- `APENL-4N9L1-2KA9D-3JX0-44LSK`
- `SDFK9-J4HUL-1JK9I9-923J-0069K`
- `F423J-JS0AW-345JD-AA05K-NMF09`

## Running the Server
Running the server for this project is easy through the use of Docker. Simply navigate to `GoodTalk/server` in your preferred terminal and run the following commands

- `docker build -t nice-talk-example .`
- `docker run -p 443:443 nice-talk-example`

Now you can send your requests from the example client to `http://127.0.0.1:443/authenticate`. Alternatively, you can build this container image directly and push it to a remote image repository and deploy it to a containerised service. Before doing this to a production environment please ensure you understand the full impact of the code as it has **NOT** been analysed and approved for production deployments.

## Running the Client
A simple implementation of the client side code is available at `GoodTalk/main.py` with simple example interactions with the implementation code at `GoodTalk/client`. To install the requirements for the client code navigate to the `GoodTalk/client` folder and run `pip3 install -r requirements.txt`. Then afterwards you will be able to execute `main.py` without issue.

To change the example code to connect to your local server go into `main.py` and change the line

```python
apiMgr = APIManager.APIManager("https://api.sneakercopter.io")
```

To

```python
apiMgr = APIManager.APIManager("http://127.0.0.1:443")
```

## Protocol Outline
The protocol implemented in this example is focused on deciding if a given product key is valid or not. However, the scope of use goes beyond this simple interaction into entire API applications. The flow for this implementation together with key details is as follows:

- Selection of a private key that is shared by both client and server (Located in `GoodTalk/client/APIRequest.py` for client and `GoodTalk/server/ServerUtils.py`, defined as `PleaseDontFindMe!`).
- **IMPORTANT:** Key selection and protection is the task of the built binary on the client side and it is strongly encouraged to not store the key in plaintext within the binary and recommended to use a key derivation function instead.
- When making a request to the API, first the request itself is defined. For the authentication example presented here JSON requests are used and the authentication data is defined as follows: 
```json
{
    "key": "THIS-IS-MY-KEY",
    "version": "0.0.1"
}
```
- This JSON object is then taken and a randomised nonce (Number You Only Use Once) is added to the payload. It is important that this value is unique every time per request as it will ensure that the following message hash will be unique despite the key and version staying the same. The current object is now
```json
{
    "key": "THIS-IS-MY-KEY",
    "nonce": "Q4DEW3W45rcC4u",
    "version": "0.0.1"
}
```
- Finally, a hash is made of the entire request body thus far. This hash is referred to as an HMAC (Hashed Message Authentication Code). The HMAC takes the secret key we previously defined is added to the JSON string to ensure that a verification HMAC cannot be computed without the key. We use SHA256 as the method in this example as there are no known collision methods. The object with this hash attached now is
```json
{
    "key": "THIS-IS-MY-KEY",
    "nonce": "De973VUBl1pkVu",
    "version": "0.0.1",
    "hmac": "c1af4187222e8c2c96d44c2ff3bcd83e64bcb809de48e51a5cbd8316acd1c19a"
}
```
- This message is now sent to the API. Upon receiving the request, the server will reconstruct the exact same message it recieved except *without* the HMAC. It will then calculate the HMAC value itself and compare it to the one provided by the client to verify the message has not been tampered with during transmission. **Only** once this is completed the server goes on to validate the version and key, if the hash does not match the message is dropped immediately.
- When the server is ready to reply, it will follow a similar process as the client did when constructing a response. The key difference is that the server also repeats the `nonce` and `hmac` values back to the client within the response JSON. In the case of this example, on a successful authentication the whole client message is also sent back to indicate that the key was valid. This request with a new server nonce added looks as follows:
```json
{
    "key": "THIS-IS-MY-KEY",
    "nonce": "De973VUBl1pkVu",
    "version": "0.0.1",
    "hmac": "c1af4187222e8c2c96d44c2ff3bcd83e64bcb809de48e51a5cbd8316acd1c19a",
    "serverNonce": "ZM7a7WI_RioPOE"
}
```
- The server adds an additional nonce to the request to ensure that repeated responses with the same initial content will generate a completely unique server signature each time. This signature is constructed in the same way the `hmac` value was during the client request generation. The whole message is converted to a string and the secret key is added to the string to ensure the hash cannot be trivially derived without it. The final response request then will be sent as the following object:
```json
{
    "key": "THIS-IS-MY-KEY",
    "nonce": "De973VUBl1pkVu",
    "version": "0.0.1",
    "hmac": "c1af4187222e8c2c96d44c2ff3bcd83e64bcb809de48e51a5cbd8316acd1c19a",
    "serverNonce": "ZM7a7WI_RioPOE",
    "serverSignature": "adb74962dcb68527b6c538c0664a22fcc7b93730e99a3ad28dc818db2d8c4299"
}
```
- Once the server response arrives at the client, the first task the client **must** do is to verify the server response. The unique step in this process is to validate that the `hmac` and `nonce` that have been returned are also the same ones that were initially sent. This is **vitally important** to keep track of as it prevents the reuse of `serverSignature` values from other requests. If this does not match, you may assume that the communication has been comprimised and let your application react appropriately.
- If all checks out however, the final step is to validate the `serverSignature`. This is done in the same way the initial `hmac` was checked. A new JSON object is created including all response values except for the `serverSignature`. The JSON object is then hashed in the same way that the original `hmac` was created by the client and is checked to ensure that the value the client calculated matches the returned `serverSignature`. If it is not a match, you may assume that the communication has been comprimised and let your application react appropriately.
- The transaction is now complete and you can assume with a high certainty that as long *as the secret key has not been comprimised* that the messages from both the client and server were sent and recieved without tampering during transmission. This is validated through the random selection of `nonce` values and validation of `hmac` and `serverSignature` by both the client and server.

## Outside of Scope
It is strongly encouraged to implement SSL into your implementation of this protocol to add another layer of protection and to stop the reading of sensitive values during transmission on public networks. This can be further solidified through the use of SSL pinning on the client side but this is outside of the scope of this project.

