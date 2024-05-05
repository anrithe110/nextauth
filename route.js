import NextAuth from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import User from "@/models/User";
import connectMongoDB from "@/libs/mongodb";
import { verifyPassword } from "@/libs/auth";

export const authOptions = {
  session: {
    strategy: "jwt",
  },
  providers: [
    CredentialsProvider({
      async authorize(credentials) {
        const client = await connectMongoDB();
        try {
          console.log("Connected to MongoDB");
          const user = await User.findOne({ email: credentials.email });
          if (!user) {
            throw new Error("No user found");
          }
          const isValid = await verifyPassword(credentials.password, user.password);
          if (!isValid) {
            throw new Error("Wrong password");
          }
          return {
            name: user.name,
            email: user.email,
            role: user.role, 
          };
        } catch (error) {
          console.error("Error:", error.message);
          throw error;
        } finally {
          if (client) {
            await client.close();
            console.log("MongoDB connection closed");
          }
        }
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user }) { 
      if (user) {
        token.role = user.role;
      }
      return token; 
    },
    async session({ session, token }) { 
      if (token?.role) {
        session.user.role = token.role;
      }
      return session;
    },
  },
  secret: process.env.NEXTAUTH_SECRET,
};
const handler = NextAuth(authOptions);
export { handler as GET, handler as POST };
