package mhibe_test

import (
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/ucbrise/jedi-pairing/lang/go/bls12381"
	"github.com/ucbrise/jedi-pairing/lang/go/cryptutils"
	"github.com/ucbrise/jedi-pairing/lang/go/wkdibe"
)

// stringToAttributes 将 "001||010" 这样的前缀或完整点映射为 JEDI 的 AttributeList
func stringToAttributes(idString string, numDims int, bitLength int) wkdibe.AttributeList {
	attrs := make(wkdibe.AttributeList)
	dims := strings.Split(idString, "||")

	for d := 0; d < numDims; d++ {
		dimPrefix := dims[d]
		for i := 0; i < len(dimPrefix); i++ {
			// 计算在 WKD-IBE 中的全局 Index
			globalIndex := wkdibe.AttributeIndex(d*bitLength + i)

			// 将字符 "0" 或 "1" 哈希为椭圆曲线 Zp 群上的标量
			bitChar := string(dimPrefix[i])
			hashedBit := cryptutils.HashToZp(new(big.Int), []byte(bitChar))

			attrs[globalIndex] = hashedBit
		}
		// 注意：如果 len(dimPrefix) < bitLength，剩下的 Index 不会被放入 attrs
		// 在 JEDI 中，没放入的 Index 默认为“通配符”(Wildcard/Free Slot)
	}
	return attrs
}

func TestMHIBEIntegration(t *testing.T) {
	fmt.Println("=== [Phase 3] M-HIBE Integration Test ===")

	// 1. 系统初始化 (Data Owner 执行)
	// 总属性数 = 维度数 * 每维位数 = 2 * 4 = 8
	maxSlots := NumDims * BitLength
	fmt.Printf("[1. Setup] Initializing WKD-IBE with %d slots...\n", maxSlots)
	params, msk := wkdibe.Setup(maxSlots, false)

	// 2. 加密数据点 (Client 执行)
	// 假设向数据库插入一条数据，其坐标为 X=3, Y=4 (二进制 0011||0100)
	targetPoint := Point{Coords: [NumDims]int64{3, 4}}
	pointBin := pointToBinaryString(targetPoint)
	pointAttrs := stringToAttributes(pointBin, NumDims, BitLength)

	fmt.Printf("[2. Encrypt] Encrypting data for Point(3,4) -> Binary: %s\n", pointBin)
	originalMsg := new(cryptutils.Encryptable).Random()
	ciphertext := wkdibe.Encrypt(originalMsg, params, pointAttrs)

	// 3. 生成查询范围密钥 (Data Owner 授权给 Database)
	// 假设查询范围是 X[2, 5], Y[3, 6]
	query := RangeQuery{Bounds: [NumDims][2]int64{{2, 5}, {3, 6}}}
	fmt.Printf("\n[3. KeyGen] Generating keys for Range Query X[2,5] x Y[3,6]...\n")

	prefixes := MapToIDs(query) // 调用我们上一阶段写好的前缀映射算法

	// 为该范围生成的查询令牌（一组子密钥）
	var queryKeys []*wkdibe.SecretKey
	for _, prefix := range prefixes {
		prefixAttrs := stringToAttributes(prefix, NumDims, BitLength)
		// 使用主密钥为每个前缀生成带通配符的子密钥 (也可以用 QualifyKey 从上级派生)
		key := wkdibe.KeyGen(params, msk, prefixAttrs)
		queryKeys = append(queryKeys, key)
	}
	fmt.Printf("Generated %d Sub-Keys for the range query.\n", len(queryKeys))

	// 4. 查询检索与解密 (Database / Client 执行)
	fmt.Printf("\n[4. Query Evaluation] Database trying to decrypt the ciphertext using query keys...\n")
	decrypted := false

	for i, key := range queryKeys {
		// 【核心原理】在 WKD-IBE 中，解密密钥的属性必须与密文属性完全对齐。
		// 虽然我们手里只有前缀查询密钥 (比如 001||010)，但因为它是目标点 (0011||0100) 的祖先，
		// 所以我们可以直接用它 "派生(Qualify)" 出针对该数据点的专属子密钥！

		// 使用父级前缀密钥，填补上缺失的通配符，派生出针对 pointAttrs 的完整子密钥
		qualifiedKey := wkdibe.QualifyKey(params, key, pointAttrs)

		// 使用派生出的专属子密钥进行解密
		decMsg := wkdibe.Decrypt(ciphertext, qualifiedKey)

		// 比较解密出的内容是否等于原文
		if bls12381.GTEqual(&originalMsg.GT, &decMsg.GT) {
			fmt.Printf(" [SUCCESS] Ciphertext accurately decrypted using derived key from Prefix #%d: %s\n", i, prefixes[i])
			decrypted = true
			break // 解密成功，跳出
		} else {
			// 如果前缀不匹配，派生出的密钥在数学上就是无效的（一团乱码），解密自然会失败
			fmt.Printf("   [Miss] Prefix Key #%d (%s) cannot derive valid key for this point.\n", i, prefixes[i])
		}
	}

	if !decrypted {
		t.Fatalf("[FAILED] None of the range keys could decrypt the target point!")
	} else {
		fmt.Println("=== M-HIBE Cryptographic Flow Completed Successfully! ===")
	}
}
