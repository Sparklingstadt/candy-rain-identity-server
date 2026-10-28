// Command identity-server runs the Candy Rain ID OpenID Connect provider.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Sparklingstadt/candy-rain-identity-server/internal/config"
	"github.com/Sparklingstadt/candy-rain-identity-server/internal/loginlimit"
	"github.com/Sparklingstadt/candy-rain-identity-server/internal/oidc"
	"github.com/Sparklingstadt/candy-rain-identity-server/internal/user"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("identity server stopped", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load(logger)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	// Which database this instance uses, without the password, so the
	// target of migrations can be told from the logs alone.
	cc := pool.Config().ConnConfig
	logger.Info("database", "host", cc.Host, "port", cc.Port, "database", cc.Database, "user", cc.User)

	users := user.NewPostgresStore(pool)
	warnIfOverprivileged(ctx, logger, users)

	handler := oidc.New(oidc.Options{
		Issuer:        cfg.Issuer,
		Clients:       cfg.Clients,
		Users:         users,
		Avatars:       user.NewPostgresAvatarStore(pool),
		Signer:        oidc.NewSigner(cfg.SigningKey),
		SessionSecret: cfg.SessionSecret,
		LoginHint:     cfg.LoginHint,
		Logger:        logger,

		LoginFailures:  loginlimit.NewPostgresStore(pool),
		ClientIPHeader: cfg.ClientIPHeader,
	})

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", cfg.Addr, "issuer", cfg.Issuer)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// warnIfOverprivileged logs when the database role can write the store's
// "User" table. It never stops startup: the check only points at a setting
// to tighten.
func warnIfOverprivileged(ctx context.Context, logger *slog.Logger, users *user.PostgresStore) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	writable, err := users.CanModifyUsers(ctx)
	switch {
	case err != nil:
		logger.Warn("could not check the database role's privileges", "err", err)
	case writable:
		logger.Warn(`the database role can modify "User"; connect as the read-only idp_server role (migrations/003_idp_server_role.sql)`)
	}
}
