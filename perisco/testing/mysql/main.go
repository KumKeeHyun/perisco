package main

import (
	"context"
	"database/sql"
	"log"

	_ "github.com/go-sql-driver/mysql"
)

func main() {
	db, err := sql.Open("mysql", "root:example@tcp(127.0.0.1:3306)/test")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	createTableQuery := `
	CREATE TABLE IF NOT EXISTS product(
		product_id int primary key auto_increment,
		product_name text,  
        product_price int, 
		created_at datetime default CURRENT_TIMESTAMP, 
		updated_at datetime default CURRENT_TIMESTAMP
	)`
	_, err = db.ExecContext(context.Background(), createTableQuery)
	if err != nil {
		log.Fatal(err)
	}

	insertQuery := "INSERT INTO product(product_name, product_price) VALUES (?, ?)"
	stmt, err := db.PrepareContext(context.Background(), insertQuery)
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(context.Background(), "testname", 123)
	if err != nil {
		log.Printf("Error %s when inserting row into products table", err)
		log.Fatal(err)
	}

	rows, err := db.Query("SELECT product_name, product_price FROM product")
	if err != nil {
		log.Fatal(err)
	}
	var name string
	var price int
	for rows.Next() {
		err := rows.Scan(&name, &price)
		if err != nil {
			log.Fatal(err)
		}
		log.Println(name, price)
	}

	_, err = db.ExecContext(context.Background(), "DELETE FROM product Where product_name = 'testname'")
	if err != nil {
		log.Fatal(err)
	}
}
