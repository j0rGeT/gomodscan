package db

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
	"gomodscan/pkg/types"
	"path/filepath"
	"strings"
)

var (
	db *bolt.DB
)

func Dir(cacheDir string) string {
	return filepath.Join(cacheDir, "db")
}

func Path(cacheDir string) string {
	dbPath := filepath.Join(cacheDir, "trivy.db")
	return dbPath
}

func Init(cacheDir string) (err error) {
	dbPath := Path(cacheDir)
	db, err = bolt.Open(dbPath, 0600, nil)
	if err != nil {
		fmt.Println(1111)
		return err
	}
	fmt.Println("open blot db success")

	return nil
}

type Config struct {
}

func (dbc Config) Connection() *bolt.DB {
	return db
}

func (dbc Config) Put(tx *bolt.Tx, bktNames []string, key string, value interface{}) error {
	if len(bktNames) == 0 {
		return xerrors.Errorf("empty bucket name")
	}

	bkt, err := tx.CreateBucketIfNotExists([]byte(bktNames[0]))
	if err != nil {
		return xerrors.Errorf("failed to create '%s' bucket: %w", bktNames[0], err)
	}

	for _, bktName := range bktNames[1:] {
		bkt, err = bkt.CreateBucketIfNotExists([]byte(bktName))
		if err != nil {
			return xerrors.Errorf("failed to create a bucket: %w", err)
		}
	}
	v, err := json.Marshal(value)
	if err != nil {
		return xerrors.Errorf("failed to unmarshal JSON: %w", err)
	}

	return bkt.Put([]byte(key), v)
}

func (dbc Config) Get(bktNames []string, key string) (value []byte, err error) {
	err = db.View(func(tx *bolt.Tx) error {
		if len(bktNames) == 0 {
			return xerrors.Errorf("empty bucket name")
		}

		bkt := tx.Bucket([]byte(bktNames[0]))
		if bkt == nil {
			return nil
		}
		for _, bktName := range bktNames[1:] {
			bkt = bkt.Bucket([]byte(bktName))
			if bkt == nil {
				return nil
			}
		}
		value = bkt.Get([]byte(key))
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("failed to get data from db: %w", err)
	}
	return value, nil
}

type Value struct {
	Source  types.DataSource
	Content []byte
}

func (dbc Config) ForEach(bktNames []string) (map[string]Value, error) {
	if len(bktNames) < 2 {
		return nil, errors.New("bktnames is less")
	}
	rootBucket, nestedBuckets := bktNames[0], bktNames[1:]

	values := map[string]Value{}
	err := db.View(func(tx *bolt.Tx) error {
		var rootBuckets []string

		if strings.Contains(rootBucket, "::") {
			// e.g. "pip::", "rubygems::"
			prefix := []byte(rootBucket)
			c := tx.Cursor()
			for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
				rootBuckets = append(rootBuckets, string(k))
			}
		} else {
			// e.g. "GitHub Security Advisory Composer"
			rootBuckets = append(rootBuckets, rootBucket)
		}

		for _, r := range rootBuckets {
			root := tx.Bucket([]byte(r))
			if root == nil {
				continue
			}

			source, err := dbc.getDataSource(tx, r)
			if err != nil {
				return err
			}

			bkt := root
			for _, nestedBkt := range nestedBuckets {
				bkt = bkt.Bucket([]byte(nestedBkt))
				if bkt == nil {
					break
				}
			}
			if bkt == nil {
				continue
			}

			err = bkt.ForEach(func(k, v []byte) error {
				values[string(k)] = Value{
					Source:  source,
					Content: v,
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return values, nil
}
