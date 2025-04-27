package server

import (
	"log/slog"
	"net"

	"github.com/BazaarTrade/AuthProtoGen/pbA"
	"github.com/BazaarTrade/AuthService/internal/service"
	"google.golang.org/grpc"
)

type Server struct {
	pbA.UnimplementedAuthServer
	grpcServer *grpc.Server
	service    *service.Service
	logger     *slog.Logger
}

func New(service *service.Service, logger *slog.Logger) *Server {
	return &Server{
		service: service,
		logger:  logger,
	}
}

func (s *Server) Run(GRPC_PORT string) error {
	lis, err := net.Listen("tcp", GRPC_PORT)
	if err != nil {
		s.logger.Error("failed to listen", "error", err)
		return err
	}

	s.grpcServer = grpc.NewServer()

	pbA.RegisterAuthServer(s.grpcServer, s)

	s.logger.Info("server is listening on port" + GRPC_PORT)

	if err := s.grpcServer.Serve(lis); err != nil {
		s.logger.Error("failed to serve", "err", err)
		return err
	}
	return nil
}

func (s *Server) Stop() {
	s.grpcServer.GracefulStop()
}
