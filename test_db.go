package main

import (
	"fmt"
	"log"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	dsn := "host=localhost user=hunter password=hunter123 dbname=hunter port=5432 sslmode=disable"

	fmt.Println("正在连接数据库...")
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("连接失败: %v", err)
	}

	fmt.Println("✅ 数据库连接成功!")

	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("获取数据库实例失败: %v", err)
	}

	if err := sqlDB.Ping(); err != nil {
		log.Fatalf("Ping 失败: %v", err)
	}

	fmt.Println("✅ 数据库 Ping 成功!")
}
