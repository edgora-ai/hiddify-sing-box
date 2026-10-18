package udptrace

import "context"

type managerContextKey struct{}

func ContextWithManager(ctx context.Context, manager *Manager) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	// A typed nil shadows any manager inherited from a different Box.
	return context.WithValue(ctx, managerContextKey{}, manager)
}

func ManagerFromContext(ctx context.Context) *Manager {
	if ctx == nil {
		return nil
	}
	manager, _ := ctx.Value(managerContextKey{}).(*Manager)
	return manager
}
