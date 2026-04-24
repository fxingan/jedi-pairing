package mhibe_test

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

// ==========================================
// 1. 数据结构定义
// ==========================================

const (
	NumDims   = 2 // 为了测试直观，这里设为 2 维。可以轻松扩展到 10 维
	BitLength = 4 // 设每个维度数据为 4 bit，即数值范围 [0, 15]
)

// Point 多维数据点
type Point struct {
	Coords [NumDims]int64
}

// RangeQuery 多维范围查询
type RangeQuery struct {
	Bounds [NumDims][2]int64 // 每一维都是 [min, max]
}

// ==========================================
// 2. 映射算法 (核心逻辑)
// ==========================================

// MapToIDs 将高维范围查询映射为一维 HIBE ID 前缀的集合
func MapToIDs(query RangeQuery) []string {
	var dimCovers [][]string

	// 1. 对每一维分别计算规范覆盖 (Canonical Covering)
	for i := 0; i < NumDims; i++ {
		minVal := query.Bounds[i][0]
		maxVal := query.Bounds[i][1]

		// 初始节点为整个空间 [0, 2^BitLength - 1]
		maxDomain := int64(math.Pow(2, BitLength)) - 1
		cover := getCanonicalCover(minVal, maxVal, 0, maxDomain, "")
		dimCovers = append(dimCovers, cover)
	}

	// 2. 对所有维度的覆盖进行笛卡尔积组合
	return cartesianProduct(dimCovers)
}

// getCanonicalCover 递归计算一维区间的规范覆盖
// min, max: 查询的目标区间
// nodeMin, nodeMax: 当前二叉树节点代表的区间
// prefix: 当前节点的二进制前缀
func getCanonicalCover(min, max, nodeMin, nodeMax int64, prefix string) []string {
	// 情况A：当前节点区间完全在查询区间内，直接返回该前缀
	if min <= nodeMin && nodeMax <= max {
		return []string{prefix}
	}
	// 情况B：当前节点区间与查询区间完全无交集，返回空
	if nodeMax < min || nodeMin > max {
		return nil
	}

	// 情况C：部分相交，分裂为左右子树继续递归
	mid := nodeMin + (nodeMax-nodeMin)/2

	// 左子树加 "0"，右子树加 "1"
	leftCover := getCanonicalCover(min, max, nodeMin, mid, prefix+"0")
	rightCover := getCanonicalCover(min, max, mid+1, nodeMax, prefix+"1")

	return append(leftCover, rightCover...)
}

// cartesianProduct 计算多个字符串切片的笛卡尔积，使用 "||" 分隔
func cartesianProduct(dimCovers [][]string) []string {
	if len(dimCovers) == 0 {
		return nil
	}

	result := dimCovers[0]
	for i := 1; i < len(dimCovers); i++ {
		var temp []string
		for _, res := range result {
			for _, cover := range dimCovers[i] {
				// 使用 "||" 拼接不同维度的前缀
				temp = append(temp, res+"||"+cover)
			}
		}
		result = temp
	}
	return result
}

// ==========================================
// 3. 辅助与验证函数
// ==========================================

// pointToBinaryString 将数据点转换为等长的二进制字符串 (用于匹配验证)
func pointToBinaryString(p Point) string {
	var parts []string
	for i := 0; i < NumDims; i++ {
		// 格式化为固定长度的二进制串，例如 4bit: 0010
		binStr := fmt.Sprintf("%0*b", BitLength, p.Coords[i])
		parts = append(parts, binStr)
	}
	return strings.Join(parts, "||")
}

// matchPrefix 检查一个数据点的二进制串是否匹配查询生成的 HIBE ID 前缀
func matchPrefix(pointBin string, prefixID string) bool {
	// 因为用 "||" 分隔，我们按维度拆开逐个比对前缀
	pointDims := strings.Split(pointBin, "||")
	prefixDims := strings.Split(prefixID, "||")

	for i := 0; i < NumDims; i++ {
		if !strings.HasPrefix(pointDims[i], prefixDims[i]) {
			return false
		}
	}
	return true
}

// ==========================================
// 4. 单元测试
// ==========================================

func TestMapToIDs(t *testing.T) {
	// 定义你的测试范围：X轴 [2, 5]，Y轴 [3, 6]
	query := RangeQuery{
		Bounds: [NumDims][2]int64{
			{2, 5},
			{3, 6},
		},
	}

	// 1. 生成前缀 ID 集合
	ids := MapToIDs(query)
	fmt.Printf("Range Query: X[2, 5], Y[3, 6]\n")
	fmt.Printf("Generated HIBE IDs (Canonical Cover):\n")
	for _, id := range ids {
		fmt.Printf("  - %s\n", id)
	}
	// 期望 X[2, 5] 会被分解为 "001"(2,3不全是，等等...), 实际是:
	// X: [2, 3] -> 001, [4, 5] -> 010 (假设4bit，0010是2, 0011是3 -> 前缀 001)

	// 2. 验证覆盖的正确性 (无遗漏，无误杀)
	matchCount := 0
	expectedCount := (5 - 2 + 1) * (6 - 3 + 1) // 4 * 4 = 16 个点

	// 遍历整个 4-bit x 4-bit 的空间 [0, 15] x [0, 15]
	for x := int64(0); x <= 15; x++ {
		for y := int64(0); y <= 15; y++ {
			p := Point{Coords: [NumDims]int64{x, y}}
			binStr := pointToBinaryString(p)

			// 检查该点是否命中生成的前缀
			hitPrefix := ""
			hitCount := 0
			for _, id := range ids {
				if matchPrefix(binStr, id) {
					hitPrefix = id
					hitCount++
				}
			}

			inRange := (x >= 2 && x <= 5) && (y >= 3 && y <= 6)

			// 断言 1: 如果在查询范围内，必须精确命中 1 个前缀 (不能是 0 个，也不能重叠命中 2 个)
			if inRange {
				if hitCount != 1 {
					t.Fatalf("Point %v (Bin: %s) is IN range but hit %d prefixes!", p.Coords, binStr, hitCount)
				}
				matchCount++
			} else {
				// 断言 2: 如果在查询范围外，必须命中 0 个前缀 (不能误杀)
				if hitCount > 0 {
					t.Fatalf("Point %v (Bin: %s) is OUT OF range but incorrectly hit prefix %s!", p.Coords, binStr, hitPrefix)
				}
			}
		}
	}

	if matchCount != expectedCount {
		t.Fatalf("Expected %d matches, but got %d", expectedCount, matchCount)
	}

	fmt.Printf("\n[Success] Verified all 256 points in space. Exact match for the %d points in range, no false positives!\n", expectedCount)
}
