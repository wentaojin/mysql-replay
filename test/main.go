package main

import (
	"context"
	"database/sql"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"golang.org/x/sync/errgroup"
)

func main() {
	db, err := sql.Open("mysql", `root:@tcp(120.92.108.85:4000)/marvin?charset=utf8mb4`)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()

	g, gCtx := errgroup.WithContext(ctx)

	g.Go(func() error {
		stmt00, err := db.PrepareContext(gCtx, `select * from sbtest1 where id = ?`)
		if err != nil {
			panic(err)
		}
		defer stmt00.Close()

		for i := 0; i < 1000; i++ {
			if _, err := stmt00.ExecContext(gCtx, i); err != nil {
				return err
			}
		}
		return nil
	})

	g.Go(func() error {
		stmt00, err := db.PrepareContext(gCtx, `select * from sbtest2 where id = ?`)
		if err != nil {
			panic(err)
		}
		defer stmt00.Close()

		for i := 0; i < 10; i++ {
			if _, err := stmt00.ExecContext(gCtx, i); err != nil {
				return err
			}
		}
		return nil
	})

	g.Go(func() error {
		stmt01, err := db.PrepareContext(gCtx, `select * from sbtest3 where id = ?`)
		if err != nil {
			panic(err)
		}
		defer stmt01.Close()
		for {
			for i := 0; i < 10; i++ {
				if _, err := stmt01.ExecContext(gCtx, i); err != nil {
					panic(err)
				}
			}
			time.Sleep(2 * time.Second)
		}
	})

	g.Go(func() error {
		_, err := db.ExecContext(gCtx, `select * from sbtest4 where id = ?`, 2)
		if err != nil {
			panic(err)
		}
		return nil
	})

	g.Go(func() error {
		for {
			_, err := db.ExecContext(gCtx, `select * from sbtest5 where id = 1000`)
			if err != nil {
				panic(err)
			}
			time.Sleep(5 * time.Second)
		}
	})

	if err := g.Wait(); err != nil {
		panic(err)
	}
}
