package main

type Scenario interface {
	Run() ([]result, error)
}
