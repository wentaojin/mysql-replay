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
		stmt00, err := db.PrepareContext(ctx, `select * from t1 where id = ?`)
		if err != nil {
			panic(err)
		}
		defer stmt00.Close()

		for i := 0; i < 100; i++ {
			if _, err := stmt00.ExecContext(gCtx, i); err != nil {
				return err
			}
			time.Sleep(1 * time.Second)
		}
		return nil
	})

	g.Go(func() error {
		stmt00, err := db.PrepareContext(ctx, `select * from t1 where id = ?`)
		if err != nil {
			panic(err)
		}
		defer stmt00.Close()

		for i := 0; i < 10; i++ {
			if _, err := stmt00.ExecContext(gCtx, i); err != nil {
				return err
			}
			time.Sleep(1 * time.Second)
		}
		return nil
	})

	g.Go(func() error {
		stmt01, err := db.PrepareContext(ctx, `select * from t2 where a = ?`)
		if err != nil {
			panic(err)
		}
		defer stmt01.Close()
		for {
			for i := 0; i < 10; i++ {
				if _, err := stmt01.ExecContext(ctx, i); err != nil {
					panic(err)
				}
			}
			time.Sleep(2 * time.Second)
		}
	})

	g.Go(func() error {
		_, err := db.ExecContext(ctx, `select * from t2 where a = ?`, 2)
		if err != nil {
			panic(err)
		}
		return nil
	})

	g.Go(func() error {
		for {
			_, err := db.ExecContext(ctx, `select * from t2 where a = 1`)
			if err != nil {
				panic(err)
			}
			time.Sleep(2 * time.Second)
		}
	})

	if err := g.Wait(); err != nil {
		panic(err)
	}
}
