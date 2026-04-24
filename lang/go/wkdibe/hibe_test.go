package wkdibe_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/ucbrise/jedi-pairing/lang/go/bls12381"
	"github.com/ucbrise/jedi-pairing/lang/go/cryptutils"
	"github.com/ucbrise/jedi-pairing/lang/go/wkdibe"
)

// TestHIBEFlow 演示如何使用 WKD-IBE 模拟 HIBE 的密钥派生和加解密流程
func TestHIBEFlow(t *testing.T) {
	// ==========================================
	// 1. 系统初始化 (Setup)
	// ==========================================
	// 假设 HIBE 最大深度为 5 (即最多支持 5 层层级)
	maxDepth := 5
	fmt.Println("[Step 1] Setting up HIBE system with max depth:", maxDepth)

	// Setup 返回公共参数 (Params) 和主密钥 (MasterKey - 即 Root Key)
	params, msk := wkdibe.Setup(maxDepth, false)

	// ==========================================
	// 2. 定义层级身份 (Identities)
	// ==========================================
	// 我们模拟路径: Root -> "01" -> "011"
	idLevel1Str := "01"
	idLevel2Str := "011"

	// 将字符串 ID 哈希映射到 Zp 群元素 (big.Int)
	idLevel1 := cryptutils.HashToZp(new(big.Int), []byte(idLevel1Str))
	idLevel2 := cryptutils.HashToZp(new(big.Int), []byte(idLevel2Str))

	fmt.Printf("[Step 2] Defined Hierarchy: Root -> %s -> %s\n", idLevel1Str, idLevel2Str)

	// ==========================================
	// 3. 生成一级子密钥 (KeyGen)
	// ==========================================
	// HIBE 第一层对应属性 Index 0
	attrsLevel1 := wkdibe.AttributeList{
		0: idLevel1,
	}

	fmt.Println("[Step 3] Generating Key for Level 1 (Root -> '01')...")
	// 使用 MasterKey 生成第一层私钥
	skLevel1 := wkdibe.KeyGen(params, msk, attrsLevel1)

	// ==========================================
	// 4. 派生二级孙密钥 (Delegate / QualifyKey)
	// ==========================================
	// HIBE 第二层对应属性 Index 1。
	// 注意：在 WKD-IBE 中，QualifyKey 要求属性列表包含“已有的”和“新增的”属性。
	// 所以这里属性列表包含 Index 0 (Level 1 ID) 和 Index 1 (Level 2 ID)。
	attrsLevel2 := wkdibe.AttributeList{
		0: idLevel1,
		1: idLevel2,
	}

	fmt.Println("[Step 4] Delegating Key for Level 2 (Level 1 -> '011')...")
	// 使用 skLevel1 (父密钥) 派生 skLevel2 (子密钥)
	// 这验证了 Delegate 功能：我们不需要 MasterKey，只需要上一级的私钥
	skLevel2 := wkdibe.QualifyKey(params, skLevel1, attrsLevel2)

	// ==========================================
	// 5. 加密 (Encrypt)
	// ==========================================
	// 创建一个随机消息
	message := new(cryptutils.Encryptable).Random()

	fmt.Printf("[Step 5] Encrypting message for target ID: %s/%s...\n", idLevel1Str, idLevel2Str)
	// 使用目标身份 (Level 2 的完整属性集) 进行加密
	ciphertext := wkdibe.Encrypt(message, params, attrsLevel2)

	// ==========================================
	// 6. 解密 (Decrypt)
	// ==========================================
	fmt.Println("[Step 6] Decrypting ciphertext using Level 2 Derived Key...")

	// 使用派生出的二级密钥进行解密
	decryptedMessage := wkdibe.Decrypt(ciphertext, skLevel2)

	// ==========================================
	// 7. 验证结果
	// ==========================================
	// 比较原始消息和解密后的消息是否一致
	// 注意：Encryptable 内嵌了 bls12381.GT，我们需要比较 GT 元素
	if bls12381.GTEqual(&message.GT, &decryptedMessage.GT) {
		fmt.Println("[Success] Decryption successful! Message content matches.")
	} else {
		t.Fatal("[Failure] Decrypted message does not match original message.")
	}
}
