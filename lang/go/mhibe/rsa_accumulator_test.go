package mhibe_test

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"
)

// ==========================================
// Phase 5: 极简版 RSA 零知识累加器 (用于可验证数据库 Benchmark)
// ==========================================

// RSAAccumulator 结构体保存公共参数
type RSAAccumulator struct {
	N *big.Int // RSA 模数 N = p * q
	G *big.Int // 生成元 G
}

// Setup 初始化累加器，生成指定位数的 RSA 模数
func SetupAccumulator(bits int) (*RSAAccumulator, error) {
	// 实际生产中需要用 Safe Primes，此处为了 Benchmark 速度使用标准素数
	p, err := rand.Prime(rand.Reader, bits/2)
	if err != nil {
		return nil, err
	}
	q, err := rand.Prime(rand.Reader, bits/2)
	if err != nil {
		return nil, err
	}

	N := new(big.Int).Mul(p, q)
	// 随机选择生成元 G (在 Z_N* 中)
	G, _ := rand.Int(rand.Reader, N)

	return &RSAAccumulator{N: N, G: G}, nil
}

// HashToPrime 将任意字符串（如坐标数据或前缀）映射为一个确定性的素数
func HashToPrime(data string) *big.Int {
	h := sha256.Sum256([]byte(data))
	z := new(big.Int).SetBytes(h[:])

	// 确保是奇数
	z.Or(z, big.NewInt(1))

	// 寻找下一个素数 (确定性寻找)
	for !z.ProbablyPrime(20) {
		z.Add(z, big.NewInt(2))
	}
	return z
}

// Accumulate 将集合 S 中的所有素数累加到 G 上: A = G^(x1 * x2 * ... * xn) mod N
func (acc *RSAAccumulator) Accumulate(primes []*big.Int) *big.Int {
	product := big.NewInt(1)
	for _, p := range primes {
		product.Mul(product, p)
	}

	A := new(big.Int).Exp(acc.G, product, acc.N)
	return A
}

// ProveNonMembership 生成非成员证明 (证明 y_prime 不在 S 中)
// 返回证明: (d, b)
func (acc *RSAAccumulator) ProveNonMembership(S_primes []*big.Int, y_prime *big.Int) (*big.Int, *big.Int, error) {
	// 1. 计算 S 中所有元素的乘积 u
	u := big.NewInt(1)
	for _, p := range S_primes {
		u.Mul(u, p)
	}

	// 2. 使用扩展欧几里得算法求 a, b 使得 a*y + b*u = gcd(y, u) = 1
	a := new(big.Int)
	b := new(big.Int)
	gcd := new(big.Int).GCD(a, b, y_prime, u)

	if gcd.Cmp(big.NewInt(1)) != 0 {
		return nil, nil, fmt.Errorf("element y is not coprime to u! It might be in the set")
	}

	// 3. 计算 d = G^a mod N
	d := new(big.Int)
	if a.Sign() < 0 {
		// 如果 a 是负数，需要先求 G 的模逆元，再算指数
		invG := new(big.Int).ModInverse(acc.G, acc.N)
		absA := new(big.Int).Abs(a)
		d.Exp(invG, absA, acc.N)
	} else {
		d.Exp(acc.G, a, acc.N)
	}

	return d, b, nil
}

// VerifyNonMembership 验证非成员证明
// 检查 d^y * A^b == G mod N
func (acc *RSAAccumulator) VerifyNonMembership(A, y_prime, d, b *big.Int) bool {
	// 1. 计算 d^y mod N
	dy := new(big.Int).Exp(d, y_prime, acc.N)

	// 2. 计算 A^b mod N
	Ab := new(big.Int)
	if b.Sign() < 0 {
		invA := new(big.Int).ModInverse(A, acc.N)
		absB := new(big.Int).Abs(b)
		Ab.Exp(invA, absB, acc.N)
	} else {
		Ab.Exp(A, b, acc.N)
	}

	// 3. 计算 LHS = (d^y * A^b) mod N
	lhs := new(big.Int).Mul(dy, Ab)
	lhs.Mod(lhs, acc.N)

	// 检查 LHS 是否等于 G
	return lhs.Cmp(acc.G) == 0
}

// ==========================================
// 单元测试与 Benchmark 展示
// ==========================================

func TestRSAAccumulatorIntegration(t *testing.T) {
	fmt.Println("=== [Phase 5] RSA Accumulator Non-Membership Benchmark ===")

	// 1. 系统初始化 (2048-bit 工业级安全强度)
	fmt.Println("[1] Setting up 2048-bit RSA Accumulator...")
	acc, err := SetupAccumulator(2048)
	if err != nil {
		t.Fatal(err)
	}

	// 2. 模拟数据库真实数据点
	dbDataStrings := []string{
		"00110100", // Point (3,4)
		"01010110", // Point (5,6)
		"11110000", // Random Point
	}
	var dbPrimes []*big.Int
	for _, s := range dbDataStrings {
		dbPrimes = append(dbPrimes, HashToPrime(s))
	}

	// 数据库计算累加值 A (Data Owner 发布)
	A := acc.Accumulate(dbPrimes)
	fmt.Println("[2] Database Acc Value (A) computed over 3 real points.")

	// 3. 提取我们在 Phase 4 中生成的某一个"空区域"
	// 例如: "0010010*" (它代表这个区域里没有任何数据)
	emptyRegionPattern := "0010010*"
	emptyPrime := HashToPrime(emptyRegionPattern)
	fmt.Printf("[3] Target Empty Region: %s\n", emptyRegionPattern)

	// 4. 数据库生成零知识证明 (Prove Non-Membership)
	fmt.Println("[4] Database generating Zero-Knowledge Proof (d, b)...")
	d, b, err := acc.ProveNonMembership(dbPrimes, emptyPrime)
	if err != nil {
		t.Fatalf("Failed to generate proof: %v", err)
	}

	// 这里可以明显看出 Proof Size 是 O(1) 的！
	// d 是 2048-bit (256 字节), b 是一个系数。证明体积极小。
	fmt.Printf("    Proof Generated! Size of d: %d bytes\n", len(d.Bytes()))

	// 5. 客户端验证证明 (Verify)
	fmt.Println("[5] Client verifying the proof...")
	isValid := acc.VerifyNonMembership(A, emptyPrime, d, b)

	if isValid {
		fmt.Println("    [SUCCESS] Proof Verified! The region is mathematically proven to be empty.")
	} else {
		t.Fatalf("    [FAILED] Proof rejected!")
	}
}
