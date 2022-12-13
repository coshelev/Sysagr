﻿
Процедура ПриКомпоновкеРезультата(ДокументРезультат, ДанныеРасшифровки, СтандартнаяОбработка)
	ЭтотОбъект.КомпоновщикНастроек.Настройки.ПараметрыДанных.УстановитьЗначениеПараметра("РазрешенныеПолномчиямиСайты", РазрешенныеПолномочиямиСайты());
КонецПроцедуры

Функция РазрешенныеПолномочиямиСайты()
	Рез = "";
	Зап = Новый Запрос();
	Зап.Текст = 
	"ВЫБРАТЬ
	|	ПользователиПолномочия.ЗначениеПолномочия КАК ЗначениеПолномочия
	|ИЗ
	|	Справочник.Пользователи.Полномочия КАК ПользователиПолномочия
	|ГДЕ
	|	ПользователиПолномочия.ИмяПолномочия = &ИмяПолномочия
	|	И ПользователиПолномочия.Ссылка = &Ссылка";
	
	Зап.УстановитьПараметр("ИмяПолномочия", 	"Отчет.СвойстваИнтернетЗаявок.Макет.Инициатор");
	Зап.УстановитьПараметр("Ссылка",			ПараметрыСеанса.ТекущийПользователь);
	РезЗап = Зап.Выполнить();
	Если РезЗап.Пустой() Тогда
		Возврат Рез;
	КонецЕсли;
	Рез = РезЗап.Выгрузить().ВыгрузитьКолонку(0);
	Возврат Рез;
КонецФункции
