//go:build ignore
// +build ignore

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

// 定义接收 JSON 数据的结构
type TestData struct {
	RightShipdate uint64     `json:"right_shipdate"`
	LineItem      [][]uint64 `json:"lineitem"`
}

func main() {
	// 1. 读取 Rust 导出的 JSON 文件
	jsonFile, err := os.Open("q1_120K_test_data.json")
	if err != nil {
		fmt.Println("打开 JSON 文件失败:", err)
		return
	}
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)
	var data TestData
	json.Unmarshal(byteValue, &data)

	// 2. 初始化用于累加的变量 (对应 Q1 的 sum_qty, sum_base_price 等)
	var sumQty, sumBasePrice, sumDiscPrice, sumCharge uint64

	// 3. 执行范围查询并聚合数据
	validRowCount := 0
	for _, row := range data.LineItem {
		// row 的索引对应:
		// [0]: l_quantity, [1]: l_extendedprice, [2]: l_discount,
		// [3]: l_tax, [4]: l_returnflag, [5]: l_linestatus, [6]: l_shipdate

		l_quantity := row[0]
		l_extendedprice := row[1]
		l_discount := row[2]
		l_tax := row[3]
		l_shipdate := row[6]

		// 范围查询条件: l_shipdate <= right_shipdate
		if l_shipdate <= data.RightShipdate {
			validRowCount++

			sumQty += l_quantity
			sumBasePrice += l_extendedprice

			// 对应电路中的累加逻辑: ext * (1000 - dis)
			discPrice := l_extendedprice * (1000 - l_discount)
			sumDiscPrice += discPrice

			// 对应电路中的累加逻辑: ext * (1000 - dis) * (1000 + tax)
			sumCharge += discPrice * (1000 + l_tax)
		}
	}

	// 4. 打印最终结果，用于和 Rust 电路中的输出进行比对
	fmt.Printf("处理完成！总记录数: %d, 满足范围查询条件的记录数: %d\n", len(data.LineItem), validRowCount)
	fmt.Println("----- Go 语言聚合结果 -----")
	fmt.Printf("Sum Quantity   : %d\n", sumQty)
	fmt.Printf("Sum Base Price : %d\n", sumBasePrice)
	fmt.Printf("Sum Disc Price : %d\n", sumDiscPrice)
	fmt.Printf("Sum Charge     : %d\n", sumCharge)
}
