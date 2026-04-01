package vless

import "context"

type vlessRouteContextKey struct{}

func ContextWithVLESSRoute(ctx context.Context, route uint16) context.Context {
	return context.WithValue(ctx, (*vlessRouteContextKey)(nil), route)
}

func VLESSRouteFromContext(ctx context.Context) (uint16, bool) {
	value := ctx.Value((*vlessRouteContextKey)(nil))
	if value == nil {
		return 0, false
	}
	return value.(uint16), true
}
