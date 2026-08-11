import React from 'react';
import { StatusBar } from 'expo-status-bar';
import { StyleSheet } from 'react-native';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';
import { AdminSessionProvider, useAdminSession } from './src/context/AdminSessionContext';
import { LoginScreen } from './src/screens/LoginScreen';
import { DashboardScreen } from './src/screens/DashboardScreen';
import { colors } from './src/theme';

function Root() {
	const { session } = useAdminSession();
	return (
		<SafeAreaView style={styles.flex}>
			{session ? <DashboardScreen /> : <LoginScreen />}
			<StatusBar style="light" />
		</SafeAreaView>
	);
}

export default function App() {
	return (
		<SafeAreaProvider>
			<AdminSessionProvider>
				<Root />
			</AdminSessionProvider>
		</SafeAreaProvider>
	);
}

const styles = StyleSheet.create({
	flex: { flex: 1, backgroundColor: colors.background }
});
