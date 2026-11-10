import json
import os
import argparse
message = ''
from schnorr_lib import (
    p, y, G, point_add, sha256, lift_x_even_y,
    bytes_from_int, n, int_from_bytes, int_from_hex,
    point_mul, x, schnorr_sign, schnorr_verify
)

JSON_FILE = "data.json"  # Change this to your actual JSON file path


# Function to load JSON files safely
def load_json(file_path):
    """Load JSON data from a file safely."""
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        return None
    try:
        with open(file_path, "r") as file:
            return json.load(file)
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse JSON in '{file_path}': {e}")
        return None


def creator():
    # 生成一个随机的消息或使用现有消息
    global message
    message = "your_message_here"

    # 将消息转换为 32 字节长
    message = sha256(message.encode())  # 生成 32 字节的哈希

    # 从 users1.json 中加载数据
    with open("users1.json", "r") as file:
        user_data = json.load(file)
        private_key = user_data["users"][0]["privateKey"]
        public_key = user_data["users"][0]["publicKey"]

    # 使用私钥生成签名
    signature = schnorr_sign(message, private_key)

    # 确保 signature 是字节串类型
    if isinstance(signature, bytes):
        signature_hex = signature.hex()  # 将字节串转换为十六进制字符串
    else:
        raise TypeError(f"Expected bytes, got {type(signature)}")

    # 保存签名到 data.json 中
    data = {
        "users": [{
            "signature": signature_hex,  # 将签名保存为十六进制字符串
            "publicKey": public_key
        }]
    }

    # 保存到 data.json 文件
    with open("data.json", "w") as file:
        json.dump(data, file, indent=4)

    print(f"Signature generated and saved: {signature_hex}")


def main():
    # Load data from JSON files
    data = load_json("data.json")
    user_data = load_json("users1.json")

    if data is None or user_data is None:
        return  # Exit if files failed to load

    # Extract users from both JSON files
    users = data.get("users", [])
    user_list = user_data.get("users", [])

    # Ensure required user data exists in both files
    if not users or not user_list:
        print("Error: No users found in one or both JSON files")
        return

    # Extract first user's details from data.json
    user1 = users[0]
    signature = user1.get("signature")  # Signature from data.json
    public_key = user1.get("publicKey")  # Public key from data.json

    # Extract first user's details from users1.json
    user2 = user_list[0]
    private_key = user2.get("privateKey")
    nonce = user2.get("nonce")
    rnonce = user2.get("Rnonce")

    # Ensure all required values are available
    if None in [signature, public_key, nonce, rnonce]:
        print("Error: Missing required data in JSON files")
        return

    # Ensure public key is 32 bytes long (64 hex characters)
    if len(public_key) != 64:
        print("Error: Public key must be 64 hex characters (32 bytes).")
        return

    # Convert public key from hex to bytes
    public_key_bytes = bytes.fromhex(public_key)

    # Verify signature
    global message
    is_valid = schnorr_verify(message, public_key_bytes, bytes.fromhex(signature))
    if is_valid:
        print("YES - Signature is valid")
    else:
        print("NO - Signature is invalid")


if __name__ == "__main__":

    # Run creator function to generate and store signature
    creator()

    # Run main function to verify the signature
    main()
